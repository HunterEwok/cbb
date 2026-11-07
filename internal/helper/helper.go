// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package helper is the Go side of the helper channel (docs/design.md, "The
// service and its helper"). The service cbb, in Rust, starts cbb-helper as
// its child and talks to it only over the child's standard input and output,
// the pipes the child inherits: no socket with a name, so no other process
// can ask the helper for anything, a signature least of all.
//
// The messages are the control socket's (internal/control): a JSON header on
// one line, then Len bytes of payload. cbb sends a request with a Seq of its
// own; the helper answers it with op reply, the same Seq and Done, or with
// Error and Detail when it fails. Requests may overlap: each runs on its own
// and the answers come in the order they end.
package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/HunterEwok/cbb/internal/control"
)

// OpHello asks the helper which build it is and what it does; the answer's
// payload is a Hello in JSON.
const OpHello = "hello"

// Hello is the answer to hello.
type Hello struct {
	Version string   `json:"version"` // the helper's build, as cbb version prints it
	Ops     []string `json:"ops"`     // the operations it serves, hello among them
}

// Handler serves one request. It returns the answer's header fields and
// payload; Serve sets op, seq and done. An error becomes the answer's
// Error, with the underlying causes in Detail.
type Handler func(req *control.Message) (*control.Message, error)

// Server serves the requests of the service on the helper channel.
type Server struct {
	version  string
	handlers map[string]Handler

	mu sync.Mutex // one answer at a time on the channel
}

// New returns a server that answers hello with version and the operations
// handed to Handle.
func New(version string) *Server {
	s := &Server{version: version, handlers: map[string]Handler{}}
	s.handlers[OpHello] = s.hello
	return s
}

// Handle serves the operation op with h. It is called before Serve.
func (s *Server) Handle(op string, h Handler) { s.handlers[op] = h }

func (s *Server) hello(*control.Message) (*control.Message, error) {
	ops := make([]string, 0, len(s.handlers))
	for op := range s.handlers {
		ops = append(ops, op)
	}
	slices.Sort(ops)
	p, err := json.Marshal(Hello{Version: s.version, Ops: ops})
	if err != nil {
		return nil, err
	}
	return &control.Message{Payload: p}, nil
}

// Serve reads requests from r and writes the answers to w until r ends,
// which is how cbb stops its helper. It returns nil then, or the error
// that broke the channel.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	rd := control.NewReader(r)
	var wg sync.WaitGroup
	defer wg.Wait()
	var werr error
	for {
		req, err := rd.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("helper: reading a request: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ans := s.serve(req)
			s.mu.Lock()
			defer s.mu.Unlock()
			if werr == nil {
				werr = control.Write(w, ans)
			}
		}()
	}
}

// serve answers one request.
func (s *Server) serve(req *control.Message) *control.Message {
	ans, err := s.call(req)
	if err != nil {
		ans = &control.Message{Header: control.Header{Error: short(err), Detail: err.Error()}}
	}
	ans.Op, ans.Seq, ans.Done = control.OpReply, req.Seq, true
	return ans
}

func (s *Server) call(req *control.Message) (ans *control.Message, err error) {
	h, ok := s.handlers[req.Op]
	if !ok {
		return nil, fmt.Errorf("cbb-helper does not serve %q", req.Op)
	}
	// A bug in one handler must not take the channel, and with it every
	// other request, down: it becomes that request's error.
	defer func() {
		if p := recover(); p != nil {
			ans, err = nil, fmt.Errorf("cbb-helper failed on %q: %v", req.Op, p)
		}
	}()
	ans, err = h(req)
	if err == nil && ans == nil {
		ans = &control.Message{}
	}
	return ans, err
}

// short is the message of err without the causes it wraps, for Error;
// Detail carries all of it.
func short(err error) string {
	if u := errors.Unwrap(err); u != nil {
		msg, cause := err.Error(), u.Error()
		if len(msg) > len(cause)+2 && msg[len(msg)-len(cause)-2:] == ": "+cause {
			return msg[:len(msg)-len(cause)-2]
		}
	}
	return err.Error()
}
