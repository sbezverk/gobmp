// Borrowed from https://github.com/cisco-ie/jalapeno

package database

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	db   driver.Database
	g    driver.Graph
	cols map[string]driver.Collection
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

	g, err := ensureGraph(db, graphName)
	if err != nil {
		glog.Errorf("Failed to create Graph")
		return nil, err
	}

	// Create / Connect  collections
	cols := make(map[string]driver.Collection)

	cols[RouterName], err = ensureVertexCollection(g, RouterName)
	if err != nil {
		glog.Errorf("Failed to connect to collection %q", RouterName)
		return nil, err
	}

	cols[EPENodeName], err = ensureVertexCollection(g, EPENodeName)
	if err != nil {
		glog.Errorf("Failed to connect to collection %q", EPENodeName)
		return nil, err
	}

	cols[EPEPrefixName], err = ensureVertexCollection(g, EPEPrefixName)
	if err != nil {
		glog.Errorf("Failed to connect to collection %q", EPEPrefixName)
		return nil, err
	}

	cols[EPELinkName], err = ensureVertexCollection(g, EPELinkName)
	if err != nil {
		glog.Errorf("Failed to connect to collection %q", EPELinkName)
		return nil, err
	}

	cols[L3VPNNodeName], err = ensureVertexCollection(g, L3VPNNodeName)
	if err != nil {
		glog.Errorf("Failed to connect to collection %q", L3VPNNodeName)
		return nil, err
	}

	cols[L3VPNPrefixName], err = ensureVertexCollection(g, L3VPNPrefixName)
	if err != nil {
		glog.Errorf("Failed to connect to collection %q", L3VPNPrefixName)
		return nil, err
	}

	cols[LSNodeName], err = ensureVertexCollection(g, LSNodeName)
	if err != nil {
		glog.Errorf("Failed to connect to collection %q", LSNodeName)
		return nil, err
	}

	cols[LSLinkName], err = ensureEdgeCollection(g, LSLinkName, []string{LSNodeName}, []string{LSNodeName})
	if err != nil {
		glog.Errorf("Failed to connect to collection %q", LSLinkName)
		return nil, err
	}

	return &ArangoConn{db: db, g: g, cols: cols}, nil
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

func (a *ArangoConn) UpsertSafe(i DBObject) error {
	if i == nil {
		return ErrNilObject
	}

	var get DBObject
	key, err := i.GetKey()
	if err != nil {
		return err
	}
	switch i.GetType() {
	case RouterName:
		get = &Router{
			Key: key,
		}
	case EPENodeName:
		get = &EPENode{
			Key: key,
		}

	case EPEPrefixName:
		get = &EPEPrefix{
			Key: key,
		}

	case EPELinkName:
		get = &EPELink{
			Key: key,
		}

	case L3VPNNodeName:
		get = &L3VPNNode{
			Key: key,
		}
	case L3VPNPrefixName:
		get = &L3VPNPrefix{
			Key: key,
		}
	case LSNodeName:
		get = &LSNode{
			Key: key,
		}
	case LSLinkName:
		get = &LSLink{
			Key: key,
		}
	}

	err = a.Read(get)
	if err == ErrNotFound {
		return a.Insert(i)
	}
	if err != nil {
		return err
	}
	err = safeMerge(get, i)
	if err != nil {
		return err
	}
	return a.Upsert(i)
}

func safeMerge(original DBObject, updater DBObject) error {
	if reflect.ValueOf(updater).Kind() != reflect.Ptr || reflect.ValueOf(original).Kind() != reflect.Ptr {
		return ErrUpSafe
	}
	up := reflect.ValueOf(updater).Elem()
	ori := reflect.ValueOf(original).Elem()

	for i := 0; i < up.NumField(); i++ {
		val := up.Field(i).Interface()
		if val == reflect.Zero(reflect.TypeOf(val)).Interface() {
			up.Field(i).Set(ori.Field(i))
		}
	}
	return nil
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

func (a *ArangoConn) Query(q string, bind map[string]interface{}, obj interface{}) ([]interface{}, error) {
	if obj == nil {
		return nil, ErrNilObject
	}
	err := a.db.ValidateQuery(context.Background(), q)
	if err != nil {
		return nil, err
	}

	cursor, err := a.db.Query(context.Background(), q, bind)
	if err != nil {
		return nil, err
	}

	i := make([]interface{}, 0)

	defer cursor.Close()
	t := reflect.TypeOf(obj)
	if t == nil {
		t = reflect.TypeOf(map[string]interface{}{})
	}
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	for {
		var obj interface{}
		if t.Kind() != reflect.Struct {
			obj = reflect.New(t).Elem().Interface()
		} else {
			obj = reflect.New(t).Interface()
		}
		_, err := cursor.ReadDocument(context.Background(), &obj)
		if driver.IsNoMoreDocuments(err) {
			break
		} else if err != nil {
			// handle other errors
			return nil, err
		}
		i = append(i, obj)
	}
	return i, nil
}

// This function does not support complex types, []string does not work. Router.Interface specifically
func (a *ArangoConn) QueryOnObject(obj DBObject, ret interface{}, operators map[string]string) ([]interface{}, error) {
	if obj == nil {
		return nil, ErrNilObject
	}
	query := fmt.Sprintf("FOR i in %s RETURN i", obj.GetType())

	filter, binds, err := genFilter(obj, operators)
	if err != nil {
		return nil, err
	}
	// Add filter stuff if we have parameters
	if len(binds) != 0 {
		query = fmt.Sprintf("FOR i in %s FILTER %s RETURN i", obj.GetType(), filter)
	}

	return a.Query(query, binds, obj)
}

func genFilter(obj DBObject, operators map[string]string) (string, map[string]interface{}, error) {
	q := make([]string, 0)
	bind := make(map[string]interface{})
	typ := reflect.TypeOf(obj).Elem()
	if typ.Kind() != reflect.Struct {
		return "", nil, errors.New("expected struct type.")
	}
	val := reflect.ValueOf(obj).Elem()
	for i := 0; i < typ.NumField(); i++ {
		typField := typ.Field(i)
		valField := val.Field(i)
		t := typField.Tag.Get("json")
		t = strings.Split(t, ",")[0]
		// Only add the fields that have values and json tags defined
		if !reflect.DeepEqual(valField.Interface(), reflect.Zero(typField.Type).Interface()) {
			//Attempting to limit queries on unsupported types
			if valField.Kind() == reflect.Slice || valField.Kind() == reflect.Map || valField.Kind() == reflect.Ptr {
				return "", nil, fmt.Errorf("Unsupported type: %s", valField.Kind())
			}

			//Ensure json tag exists
			if t == "" {
				return "", nil, fmt.Errorf("Failed to fetch json field for key: %v", typField.Name)
			}

			op, ok := operators[typField.Name]
			if !ok {
				op = "=="
			}
			q = append(q, fmt.Sprintf("i.%s %s @%s", t, op, typField.Name))
			bind[typField.Name] = valField.Interface()

		}
	}

	return strings.Join(q, " && "), bind, nil
}

func (a *ArangoConn) findCollection(n string) (driver.Collection, error) {
	val, ok := a.cols[n]
	if !ok || n == "" {
		return val, ErrCollectionNotFound
	}
	return val, nil
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
