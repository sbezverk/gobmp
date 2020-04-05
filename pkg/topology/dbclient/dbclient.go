package dbclient

// DB defines required methods for a database client to support
type DB interface {
	StoreMessage(msgType int, msg interface{}) error
}

// Srv defines required method of a database server
type Srv interface {
	Start() error
	Stop() error
	GetInterface() DB
}
