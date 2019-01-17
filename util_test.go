// Copyright (c) 2018 Tim Heckman
//
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package slackmech

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const expectedUserAgent = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0`

func Test_getUA(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://locahost", nil)
	if err != nil {
		t.Fatalf("unexpected http.NewRequest() error: %s", err)
	}

	if ua := req.Header.Get("User-Agent"); ua == expectedUserAgent {
		t.Fatal("User-Agent was already set to the expected value")
	}

	setUA(req)

	if ua := req.Header.Get("User-Agent"); ua != expectedUserAgent {
		t.Fatalf(`req.Header.Get("User-Agent") = %q, want %q`, ua, expectedUserAgent)
	}
}

func Test_getReq(t *testing.T) {
	tests := []struct {
		n string
		u string
		v url.Values
		e bool
	}{
		{n: "invalid_url", u: "kjnas\\://lkamds-(#U&@(#$))", e: true},
		{n: "valid_url_no_values", u: "http://localhost"},
		{n: "valid_url_values", u: "http://localhost", v: url.Values{"q": []string{"test"}}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			var r *http.Request
			var err error

			r, err = getReq(tt.u, tt.v)
			if err != nil {
				if tt.e {
					return // no failure
				}

				t.Fatalf("getReq(%q, %v) unexpected error: %s", tt.u, tt.v, err)
			}

			if r.Method != http.MethodGet {
				t.Fatalf("r.Method = %q, want %q", r.Method, http.MethodGet)
			}

			if !strings.Contains(r.URL.String(), tt.u) {
				t.Fatalf("req.URL = %q, does not contain %q", r.URL.String(), tt.u)
			}

			if len(tt.v) > 0 && r.URL.RawQuery != tt.v.Encode() {
				t.Fatalf("r.URL.RawQuery = %q, want %q", r.URL.RawQuery, tt.v.Encode())
			}

			if ua := r.Header.Get("User-Agent"); ua != expectedUserAgent {
				t.Fatalf(`r.Header.Get("User-Agent") = %q, want %q`, ua, expectedUserAgent)
			}
		})
	}
}

func Test_postFormReq(t *testing.T) {
	tests := []struct {
		n string
		u string
		v url.Values
		e bool
	}{
		{n: "invalid_url", u: "kjnas\\://lkamds-(#U&@(#$))", e: true},
		{n: "valid_url_no_values", u: "http://localhost"},
		{n: "valid_url_values", u: "http://localhost", v: url.Values{"q": []string{"test"}}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			var r *http.Request
			var err error

			r, err = postFormReq(tt.u, tt.v)
			if err != nil {
				if tt.e {
					return // no failure
				}

				t.Fatalf("getReq(%q, %v) unexpected error: %s", tt.u, tt.v, err)
			}

			if r.Method != http.MethodPost {
				t.Fatalf("r.Method = %q, want %q", r.Method, http.MethodPost)
			}

			if !strings.Contains(r.URL.String(), tt.u) {
				t.Fatalf("req.URL = %q, does not contain %q", r.URL.String(), tt.u)
			}

			if ua := r.Header.Get("User-Agent"); ua != expectedUserAgent {
				t.Fatalf(`r.Header.Get("User-Agent") = %q, want %q`, ua, expectedUserAgent)
			}

			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Fatalf(`r.Header.Get("Content-Type") = %q, want expectedUserAgent`, ct)
			}

			defer func() { _ = r.Body.Close() }()

			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("unexpected error reading body: %s", err)
			}

			if b, e := string(body), tt.v.Encode(); b != e {
				t.Fatalf("body = %q, want %q", b, e)
			}
		})
	}
}
