package http

import "net/http"

// statusRecorder wraps http.ResponseWriter to capture the HTTP status code and
// track whether the response header has been committed. The gateway uses it to
// record metrics and to avoid writing a double response when the upstream
// transport has already written an error.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{ResponseWriter: w}
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.written = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.written {
		// Implicit 200 — commit it through WriteHeader so both the wrapper
		// state and the underlying ResponseWriter are updated via one path.
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// Status returns the status code written to the response.
// If no explicit status was set it returns 200, consistent with net/http's default.
func (s *statusRecorder) Status() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

// Written reports whether WriteHeader or Write has been called on this recorder.
func (s *statusRecorder) Written() bool {
	return s.written
}
