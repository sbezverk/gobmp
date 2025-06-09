package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"net/http"
	_ "net/http/pprof"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/dumper"
	"github.com/sbezverk/gobmp/pkg/filer"
	"github.com/sbezverk/gobmp/pkg/gobmpsrv"
	"github.com/sbezverk/gobmp/pkg/kafka"
	"github.com/sbezverk/gobmp/pkg/nats"
	"github.com/sbezverk/gobmp/pkg/pub"
	"github.com/sbezverk/tools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile           string
	dstPort           int
	tlsPort           int
	tlsCert           string
	tlsKey            string
	tlsCA             string
	srcPort           int
	perfPort          int
	kafkaSrv          string
	kafkaTpRetnTimeMs string // Kafka topic retention time in ms
	natsSrv           string
	intercept         string
	splitAF           string
	dump              string
	file              string
)

var rootCmd = &cobra.Command{
	Use:   "gobmp",
	Short: "Go BMP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
}

func init() {
	runtime.GOMAXPROCS(1)
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gobmp.yaml)")
	rootCmd.PersistentFlags().IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	rootCmd.PersistentFlags().IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
	rootCmd.PersistentFlags().IntVar(&tlsPort, "tls-port", 0, "port for BMP over TLS (BMPS) session")
	rootCmd.PersistentFlags().StringVar(&tlsCert, "tls-cert", "", "TLS server certificate file")
	rootCmd.PersistentFlags().StringVar(&tlsKey, "tls-key", "", "TLS server key file")
	rootCmd.PersistentFlags().StringVar(&tlsCA, "tls-ca", "", "CA certificate for client verification")
	rootCmd.PersistentFlags().StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	rootCmd.PersistentFlags().StringVar(&kafkaTpRetnTimeMs, "kafka-topic-retention-time-ms", "900000", "Kafka topic retention time in ms, default is 900000 ms i.e 15 minutes")
	rootCmd.PersistentFlags().StringVar(&natsSrv, "nats-server", "", "URL to access NATS server")
	rootCmd.PersistentFlags().StringVar(&intercept, "intercept", "false", "When intercept set \"true\", all incomming BMP messges will be copied to TCP port specified by destination-port, otherwise received BMP messages will be published to Kafka.")
	rootCmd.PersistentFlags().StringVar(&splitAF, "split-af", "true", "When set \"true\" (default) ipv4 and ipv6 will be published in separate topics. if set \"false\" the same topic will be used for both address families.")
	rootCmd.PersistentFlags().IntVar(&perfPort, "performance-port", 56767, "port used for performance debugging")
	rootCmd.PersistentFlags().StringVar(&dump, "dump", "", "Dump resulting messages to file when \"dump=file\", to standard output when \"dump=console\" or to NATS when \"dump=nats\"")
	rootCmd.PersistentFlags().StringVar(&file, "msg-file", "/tmp/messages.json", "Full path anf file name to store messages when \"dump=file\"")

	viper.BindPFlag("source-port", rootCmd.PersistentFlags().Lookup("source-port"))
	viper.BindPFlag("destination-port", rootCmd.PersistentFlags().Lookup("destination-port"))
	viper.BindPFlag("tls-port", rootCmd.PersistentFlags().Lookup("tls-port"))
	viper.BindPFlag("tls-cert", rootCmd.PersistentFlags().Lookup("tls-cert"))
	viper.BindPFlag("tls-key", rootCmd.PersistentFlags().Lookup("tls-key"))
	viper.BindPFlag("tls-ca", rootCmd.PersistentFlags().Lookup("tls-ca"))
	viper.BindPFlag("kafka-server", rootCmd.PersistentFlags().Lookup("kafka-server"))
	viper.BindPFlag("kafka-topic-retention-time-ms", rootCmd.PersistentFlags().Lookup("kafka-topic-retention-time-ms"))
	viper.BindPFlag("nats-server", rootCmd.PersistentFlags().Lookup("nats-server"))
	viper.BindPFlag("intercept", rootCmd.PersistentFlags().Lookup("intercept"))
	viper.BindPFlag("split-af", rootCmd.PersistentFlags().Lookup("split-af"))
	viper.BindPFlag("performance-port", rootCmd.PersistentFlags().Lookup("performance-port"))
	viper.BindPFlag("dump", rootCmd.PersistentFlags().Lookup("dump"))
	viper.BindPFlag("msg-file", rootCmd.PersistentFlags().Lookup("msg-file"))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	flag.CommandLine.Parse([]string{})
	_ = flag.Set("logtostderr", "true")

	srcPort = viper.GetInt("source-port")
	dstPort = viper.GetInt("destination-port")
	tlsPort = viper.GetInt("tls-port")
	tlsCert = viper.GetString("tls-cert")
	tlsKey = viper.GetString("tls-key")
	tlsCA = viper.GetString("tls-ca")
	kafkaSrv = viper.GetString("kafka-server")
	kafkaTpRetnTimeMs = viper.GetString("kafka-topic-retention-time-ms")
	natsSrv = viper.GetString("nats-server")
	intercept = viper.GetString("intercept")
	splitAF = viper.GetString("split-af")
	perfPort = viper.GetInt("performance-port")
	dump = viper.GetString("dump")
	file = viper.GetString("msg-file")
	// Starting performance collecting http server
	go func() {
		glog.Info(http.ListenAndServe(fmt.Sprintf(":%d", perfPort), nil))
	}()
	// Initializing publisher
	var publisher pub.Publisher
	var err error
	switch strings.ToLower(dump) {
	case "file":
		publisher, err = filer.NewFiler(file)
		if err != nil {
			glog.Errorf("failed to initialize file publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("file publisher has been successfully initialized.")
	case "console":
		publisher, err = dumper.NewDumper()
		if err != nil {
			glog.Errorf("failed to initialize console publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("console publisher has been successfully initialized.")
	case "nats":
		publisher, err = nats.NewPublisher(natsSrv)
		if err != nil {
			glog.Errorf("failed to initialize NATS publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("NATS publisher has been successfully initialized.")
	default:
		kConfig := &kafka.Config{
			ServerAddress:        kafkaSrv,
			TopicRetentionTimeMs: kafkaTpRetnTimeMs,
		}
		publisher, err = kafka.NewKafkaPublisher(kConfig)
		if err != nil {
			glog.Errorf("failed to initialize Kafka publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("Kafka publisher has been successfully initialized.")
	}

	// Initializing bmp server
	interceptFlag, err := strconv.ParseBool(intercept)
	if err != nil {
		glog.Errorf("failed to parse to bool the value of the intercept flag with error: %+v", err)
		os.Exit(1)
	}
	splitAFFlag, err := strconv.ParseBool(splitAF)
	if err != nil {
		glog.Errorf("failed to parse to bool the value of the intercept flag with error: %+v", err)
		os.Exit(1)
	}
	bmpSrv, err := gobmpsrv.NewBMPServer(srcPort, dstPort, interceptFlag, publisher, splitAFFlag, nil)
	if err != nil {
		glog.Errorf("failed to setup new gobmp server with error: %+v", err)
		os.Exit(1)
	}

	var bmpTLSSrv gobmpsrv.BMPServer
	if tlsPort != 0 {
		tlsCfg, err := gobmpsrv.LoadTLSConfig(tlsCert, tlsKey, tlsCA)
		if err != nil {
			glog.Errorf("failed to load TLS configuration: %+v", err)
			os.Exit(1)
		}
		bmpTLSSrv, err = gobmpsrv.NewBMPServer(tlsPort, dstPort, interceptFlag, publisher, splitAFFlag, tlsCfg)
		if err != nil {
			glog.Errorf("failed to setup BMPS server with error: %+v", err)
			os.Exit(1)
		}
	}
	// Starting servers
	bmpSrv.Start()
	if bmpTLSSrv != nil {
		bmpTLSSrv.Start()
	}

	stopCh := tools.SetupSignalHandler()
	<-stopCh

	bmpSrv.Stop()
	if bmpTLSSrv != nil {
		bmpTLSSrv.Stop()
	}
	return nil
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("gobmp")
		viper.AddConfigPath("/etc/gobmp")
		viper.AddConfigPath("$HOME/.gobmp")
		viper.AddConfigPath(".")
	}
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil {
		glog.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}