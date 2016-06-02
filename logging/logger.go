package logging

//go:generate counterfeiter . Logger

// Logger provides basic logging functionality. It should be safe for
// concurrent use by multiple goroutines.
type Logger interface {
	// Printf is used for info logging by a handler.
	Printf(format string, args ...interface{})
	// Warnf is used for logging warnings that are handled by a handler.
	Warnf(message string, args ...interface{})
	// Errorf is used for logging errors that are handled by a handler.
	Errorf(format string, args ...interface{})
}
