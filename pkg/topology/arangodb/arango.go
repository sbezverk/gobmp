// Borrowed from https://github.com/cisco-ie/jalapeno

package arangodb

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

type ArangoConn struct {
	db driver.Database
	//	g    driver.Graph
	//	cols map[string]driver.Collection
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

	// g, err := ensureGraph(db, graphName)
	// if err != nil {
	// 	glog.Errorf("Failed to create Graph")
	// 	return nil, err
	// }

	// Create / Connect  collections
	//	cols := make(map[string]driver.Collection)

	return &ArangoConn{db: db}, nil
	//	return &ArangoConn{db: db, g: g, cols: cols}, nil
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

func ensureGraph(db driver.Database, name string) (driver.Graph, error) {
	var g driver.Graph
	exists, err := db.GraphExists(context.Background(), name)
	if err != nil {
		return g, err
	}

	if !exists {
		// Create database
		g, err = db.CreateGraph(context.Background(), name, nil)
		if err != nil {
			return g, err
		}
	} else {
		g, err = db.Graph(context.Background(), name)
		if err != nil {
			return g, err
		}
	}
	return g, nil
}

func ensureVertexCollection(g driver.Graph, name string) (driver.Collection, error) {
	var col driver.Collection
	exists, err := g.VertexCollectionExists(context.Background(), name)
	if err != nil {
		return col, err
	}

	if !exists {
		col, err = g.CreateVertexCollection(context.Background(), name)
		if err != nil {
			return col, err
		}
	} else {
		col, err = g.VertexCollection(context.Background(), name)
		if err != nil {
			return col, err
		}
	}
	return col, nil
}

func ensureEdgeCollection(g driver.Graph, name string, from []string, to []string) (driver.Collection, error) {
	var col driver.Collection
	exists, err := g.EdgeCollectionExists(context.Background(), name)
	if err != nil {
		return col, err
	}

	if !exists {
		col, err = g.CreateEdgeCollection(context.Background(), name, driver.VertexConstraints{From: from, To: to})
		if err != nil {
			return col, err
		}
	} else {
		// ignoring vertex constraints for now
		col, _, err = g.EdgeCollection(context.Background(), name)
		if err != nil {
			return col, err
		}
	}
	return col, nil
}

// Interfaces must set their own key if they want to manage their own keys
func (a *ArangoConn) Insert(i DBObject) error {
	if i == nil {
		return ErrNilObject
	}
	_, err := getAndSetKey(i)
	if err != nil {
		return err
	}
	col, err := a.findCollection(i.GetType())
	if err != nil {
		return err
	}
	_, err = col.CreateDocument(context.Background(), i)
	return err
}

func (a *ArangoConn) Update(i DBObject) error {
	if i == nil {
		return ErrNilObject
	}

	key, err := getAndSetKey(i)
	if err != nil {
		return err
	}

	col, err := a.findCollection(i.GetType())
	if err != nil {
		return err
	}

	_, err = col.UpdateDocument(context.Background(), key, i)
	if driver.IsNotFound(err) {
		err = ErrNotFound
	}
	return err
}

func (a *ArangoConn) Upsert(i DBObject) error {
	if i == nil {
		return ErrNilObject
	}
	// Assume update
	err := a.Update(i)
	// If not found, lets add
	if err == ErrNotFound {
		return a.Insert(i)
	}
	return err
}

func (a *ArangoConn) Read(i DBObject) error {
	if i == nil {
		return ErrNilObject
	}

	k, err := i.GetKey()
	if err != nil {
		return err
	}

	col, err := a.findCollection(i.GetType())
	if err != nil {
		return err
	}

	_, err = col.ReadDocument(context.Background(), k, i)
	if err != nil {
		if driver.IsNotFound(err) {
			return ErrNotFound
		}
		return err
	}
	return err
}

func (a *ArangoConn) Delete(i DBObject) error {
	if i == nil {
		return ErrNilObject
	}

	k, err := i.GetKey()
	if err != nil {
		return err
	}

	col, err := a.findCollection(i.GetType())
	if err != nil {
		return err
	}

	_, err = col.RemoveDocument(context.Background(), k)
	if driver.IsNotFound(err) {
		err = ErrNotFound
	}
	return err
}

func (a *ArangoConn) findCollection(n string) (driver.Collection, error) {
	ok, err := a.db.CollectionExists(context.TODO(), n)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrCollectionNotFound
	}

	return a.db.Collection(context.TODO(), n)
}

func getAndSetKey(i DBObject) (string, error) {
	prevKey, err := i.GetKey()
	if err != nil {
		return "", err
	}
	err = i.SetKey()
	if err != nil {
		return "", err
	}
	key, err := i.GetKey()
	if err != nil {
		return "", err
	}

	if prevKey != key {
		return "", ErrKeyChange
	}
	return key, nil
}
