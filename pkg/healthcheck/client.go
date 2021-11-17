package healthcheck

import "os"

// init triggers healthcheck if process healthcheck argument is provided and exits process early if so
func init() {
	var healthcheck bool
	for _, f := range os.Args {
		if f == "healthcheck" {
			healthcheck = true
			break
		}
	}

	// return gracefully and continue execution
	if !healthcheck {
		return
	}

	// exit with 0 on successful check or 1 with failed check
	if err := HTTPHealthCheck(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
