package dbclient

// DBClient defines required methods for a database client to support
type DBClient interface {
	AddRecord(recordType int, record interface{}) error
	DelRecord(recordType int, record interface{}) error
}
