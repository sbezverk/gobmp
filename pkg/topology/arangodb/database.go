package arangodb

//Database is the interface definition of a database object
type Database interface {
	Insert(DBObject) error
	Update(DBObject) error
	Upsert(DBObject) error
	Read(DBObject) error
	Delete(DBObject) error
}
