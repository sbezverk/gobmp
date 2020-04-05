package messenger

// Srv defines required method of a message server
type Srv interface {
	Start() error
	Stop() error
}
