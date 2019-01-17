// Copyright (c) 2018 Tim Heckman
//
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package slackmech

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func Test_formatLogoutURL(t *testing.T) {
	tests := []struct {
		n string
		i string
		o string
	}{
		{
			n: "no_escapted_slashes",
			i: `https://slack.com/"+'signout/'+"735542886067"+'?crumb=s-1523375754-a551e3cae184433a3a3092d66500ddb0f4d5188ddf86f991af66674c4df5a901-%E2%98%83'`,
			o: `https://slack.com/signout/735542886067?crumb=s-1523375754-a551e3cae184433a3a3092d66500ddb0f4d5188ddf86f991af66674c4df5a901-%E2%98%83`,
		},
		{
			n: "escaped_slashes",
			i: `https:\/\/slack.com\/"+'signout/'+"735542886067"+'?crumb=s-1523375754-a551e3cae184433a3a3092d66500ddb0f4d5188ddf86f991af66674c4df5a901-%E2%98%83'`,
			o: `https://slack.com/signout/735542886067?crumb=s-1523375754-a551e3cae184433a3a3092d66500ddb0f4d5188ddf86f991af66674c4df5a901-%E2%98%83`,
		},
	}

	var formatted string

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			formatted = formatLogoutURL(tt.i)

			if formatted != tt.o {
				t.Errorf("formatLogoutURL(%q) = %q, want %q", tt.i, formatted, tt.o)
			}
		})
	}
}

func Test_parseInlineJsValue(t *testing.T) {
	f, err := os.Open("./testdata/session_details.html")
	if err != nil {
		t.Fatalf("error opening ./testdata/session_details.html: %s", err)
	}

	defer func() { _ = f.Close() }()

	p, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatalf("failed to read all from ./testdata/session_details.html: %s", err)
	}

	tests := []struct {
		n   string
		s   string
		e   byte
		o   string
		err string
	}{
		{n: "not_found", s: "somethingNotPresent", err: `"somethingNotPresent" not found in byte slice`},
		{n: "terminator_not_found", s: "api_token", e: '©', err: `did not find terminating byte ('©') in input`},
		{n: "api_token", s: `api_token: "`, e: '"', o: "xoxs-334538486097-REDACTED"},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			var val string
			var err error

			val, err = parseInlineJsValue(p, tt.s, tt.e)
			if err != nil {
				if len(tt.err) > 0 {
					if strings.Contains(err.Error(), tt.err) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.err, err)
				}
				t.Fatalf("parseInlineJsValue() unexpected error: %s", err)
			}

			if len(tt.err) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.err)
			}

			if val != tt.o {
				t.Fatalf("parseInlineJsValue() = %q, want %q", val, tt.o)
			}
		})
	}
}

// constants for paths to session details mock HTML files
const (
	tdSessionDetails                 = "./testdata/session_details.html"
	tdSessionDetailsMissingToken     = "./testdata/session_details_missing_token.html" /* #nosec */
	tdSessionDetailsMissingTS        = "./testdata/session_details_missing_ts.html"
	tdSessionDetailsMissingUID       = "./testdata/session_details_missing_uid.html"
	tdSessionDetailsMissingLogoutURL = "./testdata/session_details_missing_logout_url.html"
	tdSessionDetailsInvalidLogoutURL = "./testdata/session_details_invalid_logout_url.html"
)

// constants for the important values from the session details mock HTML
const (
	tdSessionToken      = "xoxs-334538486097-REDACTED" /* #nosec */
	tdSessionVersionTS  = "1523401638"
	tdSessionVersionUID = "960e24c8dab464c657ca8fd7318a5b5033fdc962"
	tdSessionLogoutURL  = `https://slack.com/signout/334538486097?crumb=s-1523401174-affe372c8bde699088fc69fb5bbb9ce5aed6455a7f70ca04e3bb52c06984a263-%E2%98%83`
)

func Test_parseSessionDetails(t *testing.T) {
	tests := []struct {
		n    string
		fn   string
		st   string
		vt   string
		vuid string
		lou  string
		err  string
	}{
		{
			n:   "empty_file",
			err: "input too short to contain valid data",
		},
		{
			n:   "missing_api_token",
			fn:  tdSessionDetailsMissingToken,
			err: "unable to find api_token in response",
		},
		{
			n:   "missing_version_ts",
			fn:  tdSessionDetailsMissingTS,
			err: "unable to find version_ts in response",
		},
		{
			n:   "missing_version_uid",
			fn:  tdSessionDetailsMissingUID,
			err: "unable to find version_uid in response",
		},
		{
			n:   "missing_boot_data.logout_url",
			fn:  tdSessionDetailsMissingLogoutURL,
			err: "unable to find boot_data.logout_url in response",
		},
		{
			n:   "invalid_boot_data.logout_url",
			fn:  tdSessionDetailsInvalidLogoutURL,
			err: "failed to validate logoutURL",
		},
		{
			n:    "valid",
			fn:   tdSessionDetails,
			vt:   tdSessionVersionTS,
			vuid: tdSessionVersionUID,
			st:   tdSessionToken,
			lou:  tdSessionLogoutURL,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			var r io.Reader

			if len(tt.fn) == 0 {
				r = bytes.NewReader(nil)
			} else {
				f, err := os.Open(tt.fn)
				if err != nil {
					t.Fatalf("failed to open %q: %s", tt.fn, err)
				}

				defer func() { _ = f.Close() }()

				r = f
			}

			var sd sessionDetails
			var err error

			sd, err = parseSessionDetails(r)
			if err != nil {
				if len(tt.err) > 0 {
					if strings.Contains(err.Error(), tt.err) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.err, err)
				}
				t.Fatalf("parseSessionDetails() unexpected error: %s", err)
			}

			if len(tt.err) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.err)
			}

			if sd.sessionToken != tt.st {
				t.Errorf("sd.sessionToken = %q, want %q", sd.sessionToken, tt.st)
			}

			if sd.versionTS != tt.vt {
				t.Errorf("sd.versionTS = %q, want %q", sd.versionTS, tt.vt)
			}

			if sd.versionUID != tt.vuid {
				t.Errorf("sd.versionUID = %q, want %q", sd.versionUID, tt.vuid)
			}

			if sd.logOutURL != tt.lou {
				t.Errorf("sd.logOutURL = %q, want %q", sd.logOutURL, tt.lou)
			}
		})
	}
}

func TestClient_getSessionDetails(t *testing.T) {
	httpc := newTestHTTPClient(nil)

	server := httptest.NewServer(muxGetSessionDetails(t))

	c := &Client{c: httpc}

	defer server.Close()

	tests := []struct {
		n string
		s string
		u string
		e string
	}{
		{n: "invalid_url", s: "://\\!~", e: "missing protocol scheme"},
		{n: "dead_server", s: "http://127.42.1.1:43852", e: `failed to get "http://127.42.1.1:43852/messages": Get http://127.42.1.1:43852/messages: dial tcp 127.42.1.1:43852: `},
		{n: "invalid_response_code", u: "/bad_response_code", e: "unexpected HTTP response status: 302 Found"},
		{n: "response_missing_api_token", u: "/missing_api_token", e: "unable to find api_token in response"},
		{n: "valid_response"},
	}

	// these tests are not safe for parallel use
	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			// reset the client and set the test URL if needed
			c.clearSessionDetails()

			endpoint := server.URL
			if len(tt.s) > 0 {
				endpoint = tt.s
			}

			if len(tt.u) > 0 {
				endpoint = endpoint + tt.u
			}

			c.endpoint = endpoint

			var sd sessionDetails
			var err error

			sd, err = c.getSessionDetails()
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("c.getSessionDetails() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if st := sd.sessionToken; st != tdSessionToken {
				t.Fatalf("c.sessionToken = %q, want %q", st, tdSessionToken)
			}

			if vts := sd.versionTS; vts != tdSessionVersionTS {
				t.Fatalf("c.versionTS = %q, want %q", vts, tdSessionVersionTS)
			}

			if vuid := sd.versionUID; vuid != tdSessionVersionUID {
				t.Fatalf("c.versionUID = %q, want %q", vuid, tdSessionVersionUID)
			}
		})
	}
}

func muxGetSessionDetails(t *testing.T) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/bad_response_code/messages", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "nowhere", http.StatusFound)
	})
	mux.HandleFunc("/missing_api_token/messages", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(tdSessionDetailsMissingToken)
		if err != nil {
			t.Fatalf("failed to open %q: %s", tdSessionDetailsMissingToken, err)
		}

		defer func() { _ = f.Close() }()

		if _, err = io.Copy(w, f); err != nil {
			t.Fatalf("failed to write body: %s", err)
		}
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(tdSessionDetails)
		if err != nil {
			t.Fatalf("failed to open %q: %s", tdSessionDetailsMissingToken, err)
		}

		defer func() { _ = f.Close() }()

		if _, err = io.Copy(w, f); err != nil {
			t.Fatalf("failed to write body: %s", err)
		}
	})

	return mux
}
