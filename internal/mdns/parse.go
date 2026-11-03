// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"errors"

	"golang.org/x/net/dns/dnsmessage"
)

// parse decodes a packet one question and one record at a time, keeping
// the ones it can read and skipping the others. dnsmessage refuses a label
// with a dot, which RFC 6763 allows in service instance names, such as
// "Mr. Smith's iPad"; a query from an Apple device often carries such names
// among its known answers, and it must not cost the questions next to them.
// Only the record types cbb uses are kept.
func parse(data []byte) (*dnsmessage.Message, error) {
	var p dnsmessage.Parser
	h, err := p.Start(data)
	if err != nil {
		return nil, err
	}
	m := &dnsmessage.Message{Header: h}
	for {
		q, err := p.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			if p.SkipQuestion() != nil {
				return m, nil
			}
			continue
		}
		m.Questions = append(m.Questions, q)
	}
	sections := []struct {
		header func() (dnsmessage.ResourceHeader, error)
		skip   func() error
		dst    *[]dnsmessage.Resource
	}{
		{p.AnswerHeader, p.SkipAnswer, &m.Answers},
		{p.AuthorityHeader, p.SkipAuthority, &m.Authorities},
		{p.AdditionalHeader, p.SkipAdditional, &m.Additionals},
	}
	for _, sec := range sections {
		for {
			h, err := sec.header()
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				break
			}
			if err == nil {
				var body dnsmessage.ResourceBody
				if body, err = parseBody(&p, h.Type); err == nil && body != nil {
					*sec.dst = append(*sec.dst, dnsmessage.Resource{Header: h, Body: body})
					continue
				}
			}
			// A record that does not decode, or of a type cbb does
			// not use: skip it and go on.
			if sec.skip() != nil {
				return m, nil
			}
		}
	}
	return m, nil
}

// parseBody reads the body of a record of a type cbb uses; for
// another type it returns nil and leaves the record to skip.
func parseBody(p *dnsmessage.Parser, t dnsmessage.Type) (dnsmessage.ResourceBody, error) {
	switch t {
	case dnsmessage.TypePTR:
		r, err := p.PTRResource()
		return &r, err
	case dnsmessage.TypeSRV:
		r, err := p.SRVResource()
		return &r, err
	case dnsmessage.TypeTXT:
		r, err := p.TXTResource()
		return &r, err
	case dnsmessage.TypeA:
		r, err := p.AResource()
		return &r, err
	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		return &r, err
	}
	return nil, nil
}
