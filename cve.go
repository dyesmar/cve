// Copyright 2020 Ramsey Dow. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cve provides a consistent mechanism for parsing, storing, and using
// CVE identifiers.
package cve

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	originYear      = 1999
	minimumSequence = 1
	baseURL         = "https://nvd.nist.gov/vuln/detail/"
)

// CVE encodes a CVE identifier as a year part and a sequence number.
// Both are 64-bit unsigned values in anticipation of mass CVE filings
// by our forthcoming AI overlords.
type CVE struct {
	Year     uint // Year part.
	Sequence uint // Sequence number.
}

// New creates a new CVE identifier from the caller-supplied year part
// and sequence number.
func New(year, sequence uint) (*CVE, error) {
	currentYear := time.Now().Year()
	if year < originYear || year > uint(currentYear) /* #nosec G115 -- false positive */ {
		return nil, fmt.Errorf("year %d out of range", year)
	}
	if sequence < minimumSequence {
		return nil, fmt.Errorf("sequence %d out of range", sequence)
	}
	return &CVE{
		Year:     year,
		Sequence: sequence,
	}, nil
}

// Parse takes a CVE indentifier as a string, e.g., CVE-2020-6629,
// and returns its CVE type representation.
func Parse(s string) (*CVE, error) {
	xs := strings.Split(s, "-")
	if len(xs) != 3 {
		return nil, errors.New("malformed CVE identifier")
	}
	if xs[0] != "CVE" {
		return nil, errors.New("missing 'CVE' prefix")
	}
	if xs[1] == "" {
		return nil, errors.New("empty year part")
	}
	if xs[2] == "" {
		return nil, errors.New("empty sequence number")
	}
	year, err := strconv.ParseUint(xs[1], 10, 64)
	if err != nil {
		return nil, errors.New("unable to parse year")
	}
	seqLen := len(xs[2])
	if seqLen > 4 && xs[2][0] == '0' {
		return nil, errors.New("5+ digit sequence numbers cannot begin with 0")
	}
	if seqLen < 4 {
		if xs[2][0] == '0' {
			return nil, errors.New("0 padded sequence number is a runt")
		}
		dx := 4 - seqLen
		padding := strings.Repeat("0", dx)
		if strings.HasPrefix(xs[2], padding) == false {
			return nil, errors.New("short sequence numbers must be 0 padded")
		}
	}
	sequence, err := strconv.ParseUint(xs[2], 10, 64)
	if err != nil {
		return nil, errors.New("unable to parse sequence number")
	}
	return New(uint(year), uint(sequence))

}

// String returns the string reprentation of the receiver.
func (c *CVE) String() string {
	return fmt.Sprintf("CVE-%d-%04d", c.Year, c.Sequence)
}

// URL returns the NVD URL representation of the receiver.
func (c *CVE) URL() (*url.URL, error) {
	url, err := url.Parse(baseURL + c.String())
	if err != nil {
		return nil, err
	}
	return url, nil
}

// MarkdownLink returns the Markdown link representation of the receiver.
// Invalid URLs will result in the empty string being returned.
func (c *CVE) MarkdownLink() string {
	url, err := c.URL()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("[%s](%s)", c.String(), url)
}
