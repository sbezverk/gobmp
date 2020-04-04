package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/kafka"
)

var (
	msgSrv  string
	dbSrv   string
	mockDB  bool
	mockMsg bool
)

func init() {
	flag.StringVar(&msgSrv, "message-server", "", "URL to the messages supplying server")
	flag.StringVar(&dbSrv, "database-server", "", "{dns name}:port or X.X.X.X:port of the graph database")
	flag.BoolVar(&mockDB, "mock-database", false, "when set to true, received messages are stored in the file")
	flag.BoolVar(&mockMsg, "mock-message", false, "when set to true, message server is disabled.")
}

var (
	onlyOneSignalHandler = make(chan struct{})
	shutdownSignals      = []os.Signal{os.Interrupt}
)

func setupSignalHandler() (stopCh <-chan struct{}) {
	close(onlyOneSignalHandler) // panics when called twice

	stop := make(chan struct{})
	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		close(stop)
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return stop
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")

	// Initializing consumer
	if !mockMsg {
		consumer, err := kafka.NewKafkaConsumer(msgSrv)
		if err != nil {
			glog.Errorf("failed to initialize message server with error: %+v", err)
			os.Exit(1)
		}
	} else {
		// TODO Add message server mock initialization
	}
	// Initializing databse client
	if !mockDB {
		dbclient, err := arango.NewDBClient(dbSrv)
		if err != nil {
			glog.Errorf("failed to initialize databse client with error: %+v", err)
			os.Exit(1)
		}
	} else {
		// TODO Add database client mock initialization
	}
	// Initializing topology server
	topoSrv, err := toposrv.NewTopologyServer(consumer, dbClient)
	if err != nil {
		glog.Errorf("fail to setup new bmp server with error: %+v", err)
		os.Exit(1)
	}
	// Starting topology server
	topoSrv.Start()

	stopCh := setupSignalHandler()
	<-stopCh

	topoSrv.Stop()
	os.Exit(0)
}
