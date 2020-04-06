package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/topology/arangodb"
	"github.com/sbezverk/gobmp/pkg/topology/dbclient"
	"github.com/sbezverk/gobmp/pkg/topology/kafkamessenger"
	"github.com/sbezverk/gobmp/pkg/topology/messenger"
	"github.com/sbezverk/gobmp/pkg/topology/mockdb"
	"github.com/sbezverk/gobmp/pkg/topology/mockmessenger"
	"github.com/sbezverk/gobmp/pkg/topology/processor"
)

var (
	msgSrvAddr string
	dbSrvAddr  string
	mockDB     bool
	mockMsg    bool
	dbName     string
	dbUser     string
	dbPass     string
)

func init() {
	flag.StringVar(&msgSrvAddr, "message-server", "", "URL to the messages supplying server")
	flag.StringVar(&dbSrvAddr, "database-server", "", "{dns name}:port or X.X.X.X:port of the graph database")
	flag.BoolVar(&mockDB, "mock-database", false, "when set to true, received messages are stored in the file")
	flag.BoolVar(&mockMsg, "mock-messenger", false, "when set to true, message server is disabled.")
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

	var dbSrv dbclient.Srv
	var err error
	// Initializing databse client
	if !mockDB {
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
	var msgSrv messenger.Srv
	if !mockMsg {
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
