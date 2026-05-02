// Package reload provides an AtomicHandler that allows the underlying
// http.Handler to be swapped at runtime without restarting the process.
//
// Design: Decorator pattern — AtomicHandler wraps any http.Handler and adds
// hot-swap capability as a cross-cutting concern. The HTTP server holds a
// *AtomicHandler; on config reload the inner handler is replaced atomically
// so in-flight requests on the old handler finish naturally while new requests
// are served by the new handler.
package reload

import (
	"net/http"
	"sync/atomic"
)

// handlerPtr is an indirection wrapper so atomic.Pointer can hold an
// http.Handler interface value. atomic.Pointer[T] requires a concrete type;
// storing *http.Handler (pointer-to-interface) is unusual and confusing,
// so we wrap it in a named struct instead.
type handlerPtr struct{ h http.Handler }

// AtomicHandler is an http.Handler whose inner handler can be replaced
// atomically via Swap. All reads and writes go through a sync/atomic.Pointer
// so swaps are safe under concurrent request load without locking.
type AtomicHandler struct {
	ptr atomic.Pointer[handlerPtr]
}

// New creates an AtomicHandler backed by h.
func New(h http.Handler) *AtomicHandler {
	ah := &AtomicHandler{}
	ah.ptr.Store(&handlerPtr{h})
	return ah
}

// ServeHTTP delegates to the current inner handler.
// Reads are sequentially consistent with Swap calls.
func (a *AtomicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.ptr.Load().h.ServeHTTP(w, r)
}

// Swap replaces the inner handler atomically. Requests already in-flight on
// the old handler complete normally; new requests see the new handler
// immediately after Swap returns.
func (a *AtomicHandler) Swap(next http.Handler) {
	a.ptr.Store(&handlerPtr{next})
}
