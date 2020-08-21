// Borrowed from https://github.com/cisco-ie/jalapeno

package arangodb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	driver "github.com/arangodb/go-driver"
	"github.com/arangodb/go-driver/http"
	"github.com/golang/glog"
)

var (
	ErrEmptyConfig = errors.New("ArangoDB Config has an empty field")
	ErrUpSafe      = errors.New("Failed to UpdateSafe. Requires *DBObjects")
	ErrNilObject   = errors.New("Failed to operate on NIL object")
	ErrNotFound    = errors.New("Document not found")
)

type ArangoConfig struct {
	URL      string `desc:"Arangodb server URL (http://127.0.0.1:8529)"`
	User     string `desc:"Arangodb server username"`
	Password string `desc:"Arangodb server user password"`
	Database string `desc:"Arangodb database name"`
}

func NewConfig() ArangoConfig {
	return ArangoConfig{}
}

type Collection interface {
	Add(string, driver.Collection)
	Delete(string)
	Check(string) (driver.Collection, bool)
}

var _ Collection = &collections{}

type collections struct {
	sync.Mutex
	store map[string]driver.Collection
}

func (c *collections) Add(name string, d driver.Collection) {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.store[name]; !ok {
		c.store[name] = d
	}
	return
}
func (c *collections) Delete(name string) {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.store[name]; ok {
		delete(c.store, name)
	}
	return
}
func (c *collections) Check(name string) (driver.Collection, bool) {
	c.Lock()
	defer c.Unlock()
	d, ok := c.store[name]
	return d, ok
}

func NewCollection() Collection {
	return &collections{
		store: make(map[string]driver.Collection),
	}
}

type ArangoConn struct {
	db driver.Database
	sync.Mutex
	collections Collection
}

var (
	ErrCollectionNotFound = fmt.Errorf("Could not find collection")
)

func NewArango(cfg ArangoConfig) (*ArangoConn, error) {
	// Connect to DB
	if cfg.URL == "" || cfg.User == "" || cfg.Password == "" || cfg.Database == "" {
		return nil, ErrEmptyConfig
	}
	if !strings.Contains(cfg.URL, "http") {
		cfg.URL = "http://" + cfg.URL
	}
	conn, err := http.NewConnection(http.ConnectionConfig{
		Endpoints: []string{cfg.URL},
	})
	if err != nil {
		glog.Errorf("Failed to create HTTP connection: %v", err)
		return nil, err
	}

	// Authenticate with DB
	conn, err = conn.SetAuthentication(driver.BasicAuthentication(cfg.User, cfg.Password))
	if err != nil {
		glog.Errorf("Failed to authenticate with arango: %v", err)
		return nil, err
	}

	c, err := driver.NewClient(driver.ClientConfig{
		Connection: conn,
	})
	if err != nil {
		glog.Errorf("Failed to create client: %v", err)
		return nil, err
	}

	db, err := ensureDatabase(c, cfg)
	if err != nil {
		glog.Errorf("Failed to create DB")
		return nil, err
	}

	return &ArangoConn{db: db, collections: NewCollection()}, nil
}

func ensureDatabase(c driver.Client, cfg ArangoConfig) (driver.Database, error) {
	var db driver.Database

	exists, err := c.DatabaseExists(context.Background(), cfg.Database)
	if err != nil {
		return db, err
	}

	if !exists {
		// Create database
		db, err = c.CreateDatabase(context.Background(), cfg.Database, nil)
		if err != nil {
			return db, err
		}
	} else {
		db, err = c.Database(context.Background(), cfg.Database)
		if err != nil {
			return db, err
		}
	}
	return db, nil
}

func (a *ArangoConn) checkCollection(name string) (driver.Collection, error) {
	a.Lock()
	defer a.Unlock()
	// Check if collection exists in the local store
	if d, ok := a.collections.Check(name); ok {
		// Collection exists in the local store, check if database has this collection

		//		ok, err := a.db.CollectionExists(context.TODO(), name)
		//		if err == nil && ok {
		// Collection also exists in the database, returning drvier's Collection interface
		return d, nil
		//		}
		// In case of an error or the collection does not exist in return, removing collection for the local store
		// for consistency

		//		a.collections.Delete(name)
		//		return nil, err
	}

	return nil, ErrCollectionNotFound
}

func (a *ArangoConn) ensureCollection(name string) (driver.Collection, error) {
	a.Lock()
	defer a.Unlock()
	// Check if Collection exists in the database
	ctx := context.TODO()
	var d driver.Collection
	var err error
	ok, err := a.db.CollectionExists(ctx, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		_, err = a.db.CreateCollection(ctx, name, &driver.CreateCollectionOptions{})
		if err != nil {
			return nil, err
		}
	}
	if d, err = a.db.Collection(ctx, name); err != nil {
		return nil, err
	}
	// Add Collection into the local store
	a.collections.Add(name, d)

	return d, nil
}
