// Copyright (c) 2018 Tim Heckman
//
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package slackmech

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const (
	tdLoginDetails             = "./testdata/login_details.html"
	tdLoginDetailsMissingCrumb = "./testdata/login_details_missing_crumb.html"
)

const (
	tdLoginDetailsCrumb  = `s-1523681453-a17c4e9381e3df00d5e13491ef4608bde2b0f4c7c185fe5ed080b2339920b2f3-☃`
	tdLoginDetailsRedir  = `/customize/emoji`
	tdLoginDetailsSignin = `1`
)

func Test_parseLoginDetails(t *testing.T) {
	tests := []struct {
		n  string
		fn string
		e  string
	}{
		{n: "missing_crumb", fn: tdLoginDetailsMissingCrumb, e: "unable to find crumb hidden input in the page"},
		{n: "valid", fn: tdLoginDetails},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.n, func(t *testing.T) {
			var ld LoginDetails
			var err error

			f, err := os.Open(tt.fn)
			if err != nil {
				t.Fatalf("failed to open %q: %s", tt.fn, err)
			}

			defer f.Close()

			ld, err = parseLoginDetails(f)
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("parseLoginDetails() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if ld.Crumb != tdLoginDetailsCrumb {
				t.Fatalf("ld.Crumb = %q, want %q", ld.Crumb, tdLoginDetailsCrumb)
			}

			if ld.Redir != tdLoginDetailsRedir {
				t.Fatalf("ld.Redir = %q, want %q", ld.Redir, tdLoginDetailsRedir)
			}

			if ld.Signin != tdLoginDetailsSignin {
				t.Fatalf("ld.Signin = %q, want %q", ld.Signin, tdLoginDetailsSignin)
			}
		})
	}
}

func TestClient_getLoginDetails(t *testing.T) {
	httpc := newTestHTTPClient(nil)

	server := httptest.NewServer(muxGetLoginDetails(t))

	defer server.Close()

	c := &Client{c: httpc}

	tests := []struct {
		n string
		u string
		l bool
		e string
	}{
		{n: "invalid_url", u: "://\\!@~", e: "missing protocol scheme"},
		{n: "bad_response_code", u: server.URL + "/bad_response_code", e: "unexpected HTTP response status: 400 Bad Request"},
		{n: "another_bad_response_code", u: server.URL + "/another_bad_response_code", e: "unexpected HTTP response status: 508 Loop Detected"},
		{n: "logged_in_unexpected_location", u: server.URL + "/logged_in_unexpected_location", e: `unexpected redirect location: "/messagez"`},
		{n: "missing_crumb", u: server.URL + "/missing_crumb", e: "failed retrieve LoginDetails"},
		{n: "logged_in", u: server.URL + "/logged_in", l: true},
		{n: "valid", u: server.URL + "/valid"},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			var ld LoginDetails
			var li bool
			var err error

			c.endpoint = tt.u

			ld, li, err = c.getLoginDetails()
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("c.getLoginDetails() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if tt.l {
				if !li {
					t.Fatal("expected to be 'logged in', but was not")
				}

				return
			}

			if li && !tt.l {
				t.Fatal("'logged in', but was expected to be logged out / getting login details")
			}

			if ld.Crumb != tdLoginDetailsCrumb {
				t.Fatalf("ld.Crumb = %q, want %q", ld.Crumb, tdLoginDetailsCrumb)
			}

			if ld.Redir != tdLoginDetailsRedir {
				t.Fatalf("ld.Redir = %q, want %q", ld.Redir, tdLoginDetailsRedir)
			}

			if ld.Signin != tdLoginDetailsSignin {
				t.Fatalf("ld.Signin = %q, want %q", ld.Signin, tdLoginDetailsSignin)
			}
		})
	}
}

func muxGetLoginDetails(t *testing.T) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/bad_response_code", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "SHOULD CAUSE ERROR")
	})

	mux.HandleFunc("/another_bad_response_code", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusLoopDetected)
		io.WriteString(w, "SHOULD CAUSE ERROR")
	})

	mux.HandleFunc("/logged_in", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/messages", http.StatusFound)
	})

	mux.HandleFunc("/logged_in_unexpected_location", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/messagez", http.StatusFound)
	})

	mux.HandleFunc("/valid", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(tdLoginDetails)
		if err != nil {
			t.Fatalf("failed to open %q: %q", tdLoginDetails, err)
		}

		defer f.Close()

		if _, err = io.Copy(w, f); err != nil {
			t.Fatalf("failed to write body: %s", err)
		}
	})

	mux.HandleFunc("/missing_crumb", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(tdLoginDetailsMissingCrumb)
		if err != nil {
			t.Fatalf("failed to open %q: %q", tdLoginDetailsMissingCrumb, err)
		}

		defer f.Close()

		if _, err = io.Copy(w, f); err != nil {
			t.Fatalf("failed to write body: %s", err)
		}
	})

	return mux
}
