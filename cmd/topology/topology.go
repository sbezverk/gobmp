package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/topology/arangodb"
	"github.com/sbezverk/gobmp/pkg/topology/dbclient"
	"github.com/sbezverk/gobmp/pkg/topology/kafkamessenger"
	"github.com/sbezverk/gobmp/pkg/topology/messenger"
	"github.com/sbezverk/gobmp/pkg/topology/mockdb"
	"github.com/sbezverk/gobmp/pkg/topology/mockmessenger"
	"github.com/sbezverk/gobmp/pkg/topology/processor"

	"net/http"
	_ "net/http/pprof"
)

var (
	msgSrvAddr string
	dbSrvAddr  string
	mockDB     string
	mockMsg    string
	dbName     string
	dbUser     string
	dbPass     string
	perfPort   = 56768
)

func init() {
	flag.StringVar(&msgSrvAddr, "message-server", "", "URL to the messages supplying server")
	flag.StringVar(&dbSrvAddr, "database-server", "", "{dns name}:port or X.X.X.X:port of the graph database")
	flag.StringVar(&mockDB, "mock-database", "false", "when set to true, received messages are stored in the file")
	flag.StringVar(&mockMsg, "mock-messenger", "false", "when set to true, message server is disabled.")
	flag.StringVar(&dbName, "database-name", "", "DB name")
	flag.StringVar(&dbUser, "database-user", "", "DB User name")
	flag.StringVar(&dbPass, "database-pass", "", "DB User's password")
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

	// Starting performance collecting http server
	go func() {
		glog.Infof("Starting performance debugging server on %d", perfPort)
		glog.Info(http.ListenAndServe(fmt.Sprintf(":%d", perfPort), nil))
	}()

	var dbSrv dbclient.Srv
	var err error
	// Initializing databse client
	isMockDB, err := strconv.ParseBool(mockDB)
	if err != nil {
		glog.Errorf("invalid mock-database parameter: %s", mockDB)
		os.Exit(1)
	}
	if !isMockDB {
		dbSrv, err = arangodb.NewDBSrvClient(dbSrvAddr, dbUser, dbPass, dbName)
		if err != nil {
			glog.Errorf("failed to initialize databse client with error: %+v", err)
			os.Exit(1)
		}
	} else {
		dbSrv, _ = mockdb.NewDBSrvClient("")
	}

	if err := dbSrv.Start(); err != nil {
		if err != nil {
			glog.Errorf("failed to connect to database with error: %+v", err)
			os.Exit(1)
		}
	}

	// Initializing new processor process
	processorSrv := processor.NewProcessorSrv(dbSrv.GetInterface())
	// Starting topology server
	processorSrv.Start()

	// Initializing messenger process
	isMockMsg, err := strconv.ParseBool(mockMsg)
	if err != nil {
		glog.Errorf("invalid mock-messenger parameter: %s", mockMsg)
		os.Exit(1)
	}
	var msgSrv messenger.Srv
	if !isMockMsg {
		msgSrv, err = kafkamessenger.NewKafkaMessenger(msgSrvAddr, processorSrv.GetInterface())
		if err != nil {
			glog.Errorf("failed to initialize message server with error: %+v", err)
			os.Exit(1)
		}
	} else {
		msgSrv, _ = mockmessenger.NewMockMessenger(processorSrv.GetInterface())
	}

	msgSrv.Start()

	stopCh := setupSignalHandler()
	<-stopCh

	msgSrv.Stop()
	//	processorSrv.Stop()
	dbSrv.Stop()

	os.Exit(0)
}
