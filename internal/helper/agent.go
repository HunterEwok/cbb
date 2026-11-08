// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/HunterEwok/cbb/internal/agent"
	"github.com/HunterEwok/cbb/internal/control"
)

// OpAgent has the helper link the user session's clipboard with the
// service, for cbb agent (internal/agent); the payload is an
// AgentRequest. The answer comes when the agent ends: when the service goes,
// when the session's display does, or when cbb closes the channel.
const OpAgent = "agent"

// AgentRequest is the payload of agent.
type AgentRequest struct {
	Socket string `json:"socket"` // the service's control socket
}

// HandleAgent serves agent, logging to logw.
func (s *Server) HandleAgent(logw io.Writer) {
	s.Handle(OpAgent, func(req *control.Message) (*control.Message, error) {
		var r AgentRequest
		if err := json.Unmarshal(req.Payload, &r); err != nil || r.Socket == "" {
			return nil, errors.New("an agent request that is not understood")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-s.closed:
				cancel()
			case <-ctx.Done():
			}
		}()
		logf := func(format string, args ...any) { fmt.Fprintf(logw, format+"\n", args...) }
		return nil, agent.Run(ctx, r.Socket, logf)
	})
}
