package http

// Config contains the http specific configuration.
type Config struct {
	Port   int      `json:"port"`
	Routes *[]Route `json:"routes"`
}

// Context is the http context
type Context struct {
	Config *Config
	Server *Server
}

// NewContext creates an http server based on provided configuration.
func NewContext(config *Config) (*Context, error) {

	server, err := NewServer(config.Port, config.Routes)
	if err != nil {
		return nil, err
	}
	context := Context{
		Config: config,
		Server: server,
	}

	return &context, nil
}
