package healthcheck

// EnableProvider enables the provider of healthcheck data
func EnableProvider(checker Checker, done <-chan struct{}) <-chan error {
	return EnableHTTPProvider(checker, done)
}
