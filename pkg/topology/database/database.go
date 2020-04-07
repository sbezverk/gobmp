package database

//Database is the interface definition of a database object
type Database interface {
	Insert(DBObject) error
	Update(DBObject) error
	Upsert(DBObject) error
	UpsertSafe(DBObject) error
	Read(DBObject) error
	Delete(DBObject) error
	Query(string, map[string]interface{}, interface{}) ([]interface{}, error)
	QueryOnObject(DBObject, interface{}, map[string]string) ([]interface{}, error)
}
