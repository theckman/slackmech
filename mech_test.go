// Copyright (c) 2018 Tim Heckman
//
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package slackmech

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/publicsuffix"
)

func newTestHTTPClient(jar *cookiejar.Jar) *http.Client {
	c := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   100 * time.Millisecond,
				KeepAlive: 2 * time.Second,
			}).DialContext,
			MaxIdleConns:          1,
			IdleConnTimeout:       1 * time.Second,
			TLSHandshakeTimeout:   1 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   1,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if jar != nil {
		c.Jar = jar
	}

	return c
}

func TestNew(t *testing.T) {
	c := &http.Client{}

	tests := []struct {
		n string
		c *http.Client
		s string
		e string
	}{
		{n: "no_client", s: "test", e: "must provide an http client"},
		{n: "no_subdomain", c: c, e: "must provide the Slack workspace subdomain"},
		{n: "client_and_subdomain", c: c, s: "test"},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			var client *Client
			var err error

			// to get around the typed nil interface check issue
			if tt.c == nil {
				client, err = New(nil, tt.s)
			} else {
				client, err = New(tt.c, tt.s)
			}

			if err != nil {
				if len(tt.e) > 0 {
					if !strings.Contains(err.Error(), tt.e) {
						t.Fatalf("%q not found in error %q", tt.e, err.Error())
					}
					return // no failure
				}
				t.Fatalf("New(%v, %q) unexpected error: %s", tt.c, tt.s, err)
			}

			if client == nil {
				t.Fatal("returned client is <nil> with no error")
			}

			if expected := "https://" + tt.s + ".slack.com"; client.endpoint != expected {
				t.Fatalf("client.endpoint = %q, want %q", client.endpoint, expected)
			}

			if client.c != c {
				t.Fatalf("client.c = %v, want %v", client.c, c)
			}
		})
	}
}

func TestClient_SessionToken(t *testing.T) {
	const expected = "42"

	c := &Client{sessionToken: expected}

	if st := c.SessionToken(); st != expected {
		t.Fatalf("c.SessionToken() = %q, want %q", st, expected)
	}
}

func TestClient_clearSessionDetails(t *testing.T) {
	c := &Client{
		logOutURL: "A", sessionToken: "B",
		versionTS: "C", versionUID: "D",
	}

	if c.logOutURL != "A" || c.sessionToken != "B" ||
		c.versionTS != "C" || c.versionUID != "D" {
		t.Fatalf("unexpected situation: %#v", c)
	}

	c.clearSessionDetails()

	tests := []struct {
		n, v string
	}{
		{n: "c.logOutURL", v: c.logOutURL},
		{n: "c.sessionToken", v: c.sessionToken},
		{n: "c.versionTS", v: c.versionTS},
		{n: "c.versionUID", v: c.versionUID},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			if tt.v != "" {
				t.Errorf(`%s = %q, want ""`, tt.n, tt.v)
			}
		})
	}
}

func TestClient_get(t *testing.T) {
	httpc := newTestHTTPClient(nil)

	server := httptest.NewServer(muxGet(t))

	c := &Client{c: httpc}

	defer server.Close()

	tests := []struct {
		n string
		u string
		v url.Values
		e bool
	}{
		{n: "invalid_url", u: "*&HD^HSE://\\!~", e: true},
		{n: "dead_server", u: "http://127.42.1.1:43852", e: true},
		{n: "valid_url_no_params", u: server.URL + "/test"},
		{n: "valid_url_params", u: server.URL + "/test_params", v: url.Values{"q": []string{"testQueryParam"}}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			var resp *http.Response
			var err error

			resp, err = c.get(tt.u, tt.v)
			if err != nil {
				if tt.e {
					return
				}
				t.Fatalf("unexpected error: %s", err)
			}

			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				t.Errorf("unexpected HTTP response %q, want %d", resp.Status, http.StatusOK)
			}

			p, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unexpected error reading response body: %s", err)
			}

			if !bytes.Equal(p, []byte("ok!")) {
				t.Fatalf("resp.Body = %q, want %q", string(p), "ok!")
			}
		})
	}
}

func muxGet(t *testing.T) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/test", getmw(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok!")
	}))
	mux.HandleFunc("/test_params", getmw(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("server failure: r.ParseForm() failed: %s", err)
		}

		if n := len(r.Form); n > 1 {
			fmt.Fprintf(w, "too many query parameters %d, want 1", n)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if q := r.FormValue("q"); q != "testQueryParam" {
			fmt.Fprintf(w, `query param "q" = %q, want "testQueryParam"`, q)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		io.WriteString(w, "ok!")
	}))

	return mux
}

func TestClient_postForm(t *testing.T) {
	httpc := newTestHTTPClient(nil)

	server := httptest.NewServer(muxPostForm(t))

	c := &Client{c: httpc}

	defer server.Close()

	tests := []struct {
		n string
		u string
		v url.Values
		e bool
	}{
		{n: "invalid_url", u: "*&HD^HSE://\\!~", e: true},
		{n: "dead_server", u: "http://127.42.1.1:43852", e: true},
		{n: "valid_url_no_params", u: server.URL + "/test"},
		{n: "valid_url_params", u: server.URL + "/test_params", v: url.Values{"q": []string{"testQueryParam"}}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			var resp *http.Response
			var err error

			resp, err = c.postForm(tt.u, tt.v)
			if err != nil {
				if tt.e {
					return
				}
				t.Fatalf("unexpected error: %s", err)
			}

			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				t.Errorf("unexpected HTTP response %q, want %d", resp.Status, http.StatusOK)
			}

			p, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unexpected error reading response body: %s", err)
			}

			if !bytes.Equal(p, []byte("ok!")) {
				t.Fatalf("resp.Body = %q, want %q", string(p), "ok!")
			}
		})
	}
}

func muxPostForm(t *testing.T) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/test", postmw(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok!")
	}))

	mux.HandleFunc("/test_params", postmw(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("server failure: r.ParseForm() failed: %s", err)
		}

		if n := len(r.Form); n > 1 {
			fmt.Fprintf(w, "too many POST parameters %d, want 1", n)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if q := r.FormValue("q"); q != "testQueryParam" {
			fmt.Fprintf(w, `POST param "q" = %q, want "testQueryParam"`, q)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		io.WriteString(w, "ok!")
	}))

	return mux
}

func TestClient_shouldRedirect(t *testing.T) {
	httpc := newTestHTTPClient(nil)

	server := httptest.NewServer(muxShouldRedirect(t))

	defer server.Close()

	c := &Client{c: httpc}

	tests := []struct {
		n string
		u string
		l string
		e bool
	}{
		{n: "invalid_url", u: "*&HD^HSE://\\!~", e: true},
		{n: "dead_server", u: "http://127.42.1.1:43852", e: true},
		{n: "valid_url_no_redir", u: server.URL + "/no_redir", e: true},
		{n: "valid_url_no_redir_param", u: server.URL + "/test", e: true},
		{n: "valid_url_invalid_redir_response", u: server.URL + `/other_loc?redir=%2Fredir`, l: "/redir", e: true},
		{n: "valid_url", u: server.URL + `/test?redir=%2Fredir`, l: "/redir"},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.n, func(t *testing.T) {
			var err error = c.shouldRedirect(tt.u, tt.l)
			if err != nil {
				if tt.e {
					return
				}
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

func muxShouldRedirect(t *testing.T) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", http.NotFound)
	mux.HandleFunc("/no_redir", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok!") })
	mux.HandleFunc("/test", getmw(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("server failure: r.ParseForm() failed: %s", err)
		}

		if n := len(r.Form); n > 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "too many query parameters %d, want 1", n)
			return
		}

		loc := r.FormValue("redir")

		if loc == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "redir query parameter cannot be empty")
			return
		}

		http.Redirect(w, r, loc, http.StatusFound)
	}))
	mux.HandleFunc("/other_loc", getmw(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("server failure: r.ParseForm() failed: %s", err)
		}

		if n := len(r.Form); n > 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "too many query parameters %d, want 1", n)
			return
		}

		loc := r.FormValue("redir")

		if loc == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "redir query parameter cannot be empty")
			return
		}

		http.Redirect(w, r, "/hopefullyNotTheLocation", http.StatusFound)
	}))

	return mux
}

const (
	tdLoginEmail    = `test@example.org`
	tdLoginPassword = `not a real password`
)

func TestClient_logIn(t *testing.T) {
	httpc := newTestHTTPClient(nil)

	server := httptest.NewServer(muxLogIn(t))

	defer server.Close()

	c := &Client{c: httpc, endpoint: server.URL}

	tests := []struct {
		n   string
		u   string
		e   string
		p   string
		ldc string // LoginDetails.Crumb
		ldr string // LoginDetails.Redir
		lds string // LoginDetails.Signin
		ldh string // LoginDetails.HasRemember
		loc string
		err string
	}{
		{
			n: "no_email", p: tdLoginPassword,
			err: "both an email and password must be provided",
		},
		{
			n: "no_password", e: tdLoginEmail,
			err: "both an email and password must be provided",
		},
		{
			n: "no_crumb", e: tdLoginEmail, p: tdLoginPassword,
			ldr: tdLoginDetailsRedir, lds: tdLoginDetailsSignin,
			ldh: tdLoginDetailsHasRemember,
			err: "LoginDetails must contain a crumb value",
		},
		{
			n: "no_signin", e: tdLoginEmail, p: tdLoginPassword,
			ldc: tdLoginDetailsCrumb, ldr: tdLoginDetailsRedir,
			ldh: tdLoginDetailsHasRemember,
			err: "LoginDetails must contain a signin value",
		},
		{
			n: "no_has_remember", e: tdLoginEmail, p: tdLoginPassword,
			ldc: tdLoginDetailsCrumb, ldr: tdLoginDetailsRedir,
			lds: tdLoginDetailsSignin,
			err: "LoginDetails must contain a has_remember value",
		},
		{
			n: "bad_url", u: ":\\//!@~",
			e: tdLoginEmail, p: tdLoginPassword,
			ldc: tdLoginDetailsCrumb, ldr: tdLoginDetailsRedir,
			lds: tdLoginDetailsSignin, ldh: tdLoginDetailsHasRemember,
			err: "missing protocol scheme",
		},
		{
			n: "bad_response_code", u: server.URL + "/bad_response_code",
			e: tdLoginEmail, p: tdLoginPassword,
			ldc: tdLoginDetailsCrumb, ldr: tdLoginDetailsRedir,
			lds: tdLoginDetailsSignin, ldh: tdLoginDetailsHasRemember,
			err: "unexpected HTTP response when logging in (400 Bad Request)",
		},
		{
			n: "another_bad_response_code", u: server.URL + "/another_bad_response_code",
			e: tdLoginEmail, p: tdLoginPassword,
			ldc: tdLoginDetailsCrumb, ldr: tdLoginDetailsRedir,
			lds: tdLoginDetailsSignin, ldh: tdLoginDetailsHasRemember,
			err: "unexpected HTTP response when logging in (508 Loop Detected)",
		},
		{
			n: "bad_login_credential", u: server.URL + "/signin",
			e: tdLoginEmail, p: "invalid pass",
			ldc: tdLoginDetailsCrumb, ldr: tdLoginDetailsRedir,
			lds: tdLoginDetailsSignin, ldh: tdLoginDetailsHasRemember,
			err: fmt.Sprintf("invalid Slack credentials for %q", server.URL+"/signin"),
		},
		{
			n: "invalid_crumb", u: server.URL + "/signin",
			e: tdLoginEmail, p: tdLoginPassword,
			ldc: "invalid crumb", ldr: tdLoginDetailsRedir,
			lds: tdLoginDetailsSignin, ldh: tdLoginDetailsHasRemember,
			err: fmt.Sprintf("failed to log in to %q for unknown reason", server.URL+"/signin"),
		},
		{
			n: "valid_credentials_unexpected_redirect", u: server.URL + "/signin_unknown_redir",
			e: tdLoginEmail, p: tdLoginPassword,
			ldc: tdLoginDetailsCrumb, ldr: "",
			lds: tdLoginDetailsSignin, ldh: tdLoginDetailsHasRemember,
			err: fmt.Sprintf(
				"unexpected HTTP redirect location header value when logging in (%q)",
				`https://slack.com/chuckcookie?redir=https%3A%2F%2Ftest.slack.com%2F`,
			),
		},
		{
			n: "valid_credentials", u: server.URL + "/signin",
			e: tdLoginEmail, p: tdLoginPassword,
			ldc: tdLoginDetailsCrumb, ldr: "",
			lds: tdLoginDetailsSignin, ldh: tdLoginDetailsHasRemember,
			loc: `https://slack.com/checkcookie?redir=https%3A%2F%2Ftest.slack.com%2F`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			if len(tt.u) > 0 {
				c.endpoint = tt.u
			}

			var loc string
			var err error

			ld := LoginDetails{Crumb: tt.ldc, Redir: tt.ldr, Signin: tt.lds, HasRemember: tt.ldh}

			loc, err = c.logIn(tt.e, tt.p, ld)
			if err != nil {
				if len(tt.err) > 0 {
					if strings.Contains(err.Error(), tt.err) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.err, err)
				}
				t.Fatalf("c.logIn() unexpected error: %s", err)
			}

			if len(tt.err) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.err)
			}

			if loc != tt.loc {
				t.Fatalf("loc = %q, want %q", loc, tt.loc)
			}
		})
	}
}

func postmw(t *testing.T, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "%q moethod not allowed, want %q", r.Method, http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form for request to %q: %s", r.URL.Path, err)
		}

		next(w, r)
	}
}

func getmw(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "%q moethod not allowed, want %q", r.Method, http.StatusMethodNotAllowed)
			return
		}

		next(w, r)
	}
}

func getpostmw(t *testing.T, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// noop
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse form for request to %q: %s", r.URL.Path, err)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "method cannot be %q must be GET or POST", r.Method)
			return
		}

		next(w, r)
	}
}

func muxLogIn(t *testing.T) *http.ServeMux {
	postlogin := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.FormValue("email") != tdLoginEmail || r.FormValue("password") != tdLoginPassword {
				fmt.Fprint(w, `Sorry, you entered an incorrect email address or password.`)
				return
			}

			if cr := r.FormValue("crumb"); cr != tdLoginDetailsCrumb {
				fmt.Fprintf(w, "crumb = %q, want %q", cr, tdLoginDetailsCrumb)
				return
			}

			if si := r.FormValue("signin"); si != tdLoginDetailsSignin {
				fmt.Fprintf(w, "signin = %q, want %q", si, tdLoginDetailsSignin)
				return
			}

			redirVals, ok := r.Form["redir"]
			if !ok {
				fmt.Fprint(w, "redir form value was not present in request")
				return
			}

			var redirQuery string
			if len(redirVals[0]) == 0 {
				redirQuery = (url.Values{"redir": []string{"https://test.slack.com/"}}).Encode()
			} else {
				redirQuery = (url.Values{"redir": []string{redirVals[0]}}).Encode()
			}

			http.Redirect(w, r, "https://slack.com/"+name+"?"+redirQuery, http.StatusFound)
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", http.NotFound)
	mux.HandleFunc("/signin", postmw(t, postlogin("checkcookie")))
	mux.HandleFunc("/signin_unknown_redir", postmw(t, postlogin("chuckcookie")))

	mux.HandleFunc("/bad_response_code", postmw(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "SHOULD CAUSE ERROR")
	}))

	mux.HandleFunc("/another_bad_response_code", postmw(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusLoopDetected)
		fmt.Fprint(w, "SHOULD CAUSE ERROR")
	}))

	return mux
}

const (
	tdStartSession               = "./testdata/start_session.html"
	tdStartSessionBadCredentials = "./testdata/start_session_bad_creds.html"
	tdStartSessionMessages       = "./testdata/start_session_messages.html"
)

const (
	tdStartSessionCrumb       = `s-1523681454-a17c4e9381e3df00d5e13491ef4608bde2b0f4c7c185fe5ed080b2339920b2f3-☃`
	tdStartSessionCookieName  = "sstest"
	tdStartSessionCookieValue = "42"
)

func TestClient_StartSession(t *testing.T) {
	cj, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		t.Fatalf("error building cookiejar: %s", err)
	}

	ms := &mockSlack{t: t}

	server := httptest.NewServer(muxStartSession(t, ms))

	defer server.Close()

	httpc := newTestHTTPClient(cj)

	c := &Client{c: httpc, endpoint: server.URL}

	tests := []struct {
		n   string
		e   string
		p   string
		err string

		rgfc      bool // when there's a cookie
		rgfnc     bool // when there's no cookie
		rpf       bool
		mf        bool
		cf        bool
		freshpots bool // dave grohl would approve
	}{
		{
			n: "no_email", p: tdLoginPassword,
			err: "both an email and password must be provided",
		},
		{
			n: "no_password", e: tdLoginEmail,
			err: "both an email and password must be provided",
		},
		{
			n: "fresh_login_getLoginDetails_fail",
			e: tdLoginEmail, p: tdLoginPassword,
			rgfnc: true, freshpots: true,
			err: "unexpected HTTP response status: 500 Internal Server Error"},
		{
			n: "fresh_login_logIn_fail",
			e: tdLoginEmail, p: "invalid pass", freshpots: true,
			err: fmt.Sprintf("invalid Slack credentials for %q", server.URL),
		},
		{
			n: "fresh_login_shouldRedirect_checkcookie_fail",
			e: tdLoginEmail, p: tdLoginPassword,
			cf: true, freshpots: true,
			err: "did not redirect as expected (500 Internal Server Error)",
		},
		{
			n: "fresh_login_shouldRedirect_root_fail",
			e: tdLoginEmail, p: tdLoginPassword,
			rgfc: true, freshpots: true,
			err: "did not redirect as expected (500 Internal Server Error)",
		},
		{
			n: "fresh_login_getSessionDetails_fail",
			e: tdLoginEmail, p: tdLoginPassword,
			mf: true, freshpots: true,
			err: "failed to get session details: unexpected HTTP response status: 500 Internal Server Error",
		},
		{n: "fresh_login", e: tdLoginEmail, p: tdLoginPassword, freshpots: true},
		{n: "second_login", e: tdLoginEmail, p: tdLoginPassword},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			if tt.freshpots {
				cj, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
				if err != nil {
					t.Fatalf("error building cookiejar for fresh pots: %s", err)
				}
				httpc.Jar = cj
			}

			c.clearSessionDetails()

			ms.rootGetFailCookie = tt.rgfc
			ms.rootGetFailNoCookie = tt.rgfnc
			ms.rootPostFail = tt.rpf
			ms.messagesFail = tt.mf
			ms.checkcookieFail = tt.cf

			var err error = c.StartSession(tt.e, tt.p)
			if err != nil {
				if len(tt.err) > 0 {
					if strings.Contains(err.Error(), tt.err) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.err, err)
				}
				t.Fatalf("c.StartSession() unexpected error: %s", err)
			}

			if len(tt.err) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.err)
			}

			if st := c.SessionToken(); st != "xoxs-334538486098-REDACTED" {
				t.Fatalf("c.SessionToken() = %q, want %q", st, "xoxs-334538486098-REDACTED")
			}
		})
	}
}

func writeFileToWriter(path string, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.Errorf("failed to open %q: %s", tdStartSession, err)
	}

	defer f.Close()

	if _, err = io.Copy(w, f); err != nil {
		return errors.Errorf("failed to write body: %s", err)
	}

	return nil
}

func cookieValid(name, value string, r *http.Request) bool {
	if cookie, err := r.Cookie(name); err == nil {
		if cookie.Value == value {
			return true
		}
	}
	return false
}

type mockSlack struct {
	rootGetFailCookie   bool
	rootGetFailNoCookie bool
	rootPostFail        bool
	messagesFail        bool
	checkcookieFail     bool
	t                   *testing.T
}

func (m *mockSlack) root(w http.ResponseWriter, r *http.Request) {
	// GET
	if r.Method == http.MethodGet {
		if cookieValid(tdStartSessionCookieName, tdStartSessionCookieValue, r) {
			if m.rootGetFailCookie {
				http.Error(w, "request configured to fail", http.StatusInternalServerError)
				log.Print("rip")
				return
			}

			http.Redirect(w, r, "/messages", http.StatusFound)
			return
		}

		if m.rootGetFailNoCookie {
			http.Error(w, "request configured to fail", http.StatusInternalServerError)
			log.Print("rip")
			return
		}

		if err := writeFileToWriter(tdStartSession, w); err != nil {
			m.t.Fatalf("failed to write file: %s", err)
		}
		return
	}

	// POST
	if m.rootPostFail {
		http.Error(w, "request configured to fail", http.StatusInternalServerError)
		return
	}

	if r.FormValue("email") != tdLoginEmail || r.FormValue("password") != tdLoginPassword {
		if err := writeFileToWriter(tdStartSessionBadCredentials, w); err != nil {
			m.t.Fatalf("failed to write file: %s", err)
		}
		return
	}

	if cr := r.FormValue("crumb"); cr != tdStartSessionCrumb {
		m.t.Logf("crumb = %q, want %q -- returning 200", cr, tdStartSessionCrumb)

		if err := writeFileToWriter(tdStartSession, w); err != nil {
			m.t.Fatalf("failed to write file: %s", err)
		}
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     tdStartSessionCookieName,
		Value:    tdStartSessionCookieValue,
		MaxAge:   61,
		HttpOnly: true,
	})

	redir := r.FormValue("redir")
	if len(redir) == 0 {
		redir = "/"
	}

	redirQuery := (url.Values{"redir": []string{redir}}).Encode()

	http.Redirect(w, r, "http://"+r.Host+"/checkcookie?"+redirQuery, http.StatusFound)
}

func (m *mockSlack) messages(w http.ResponseWriter, r *http.Request) {
	if m.messagesFail {
		http.Error(w, "request configured to fail", http.StatusInternalServerError)
		return
	}

	if !cookieValid(tdStartSessionCookieName, tdStartSessionCookieValue, r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if err := writeFileToWriter(tdStartSessionMessages, w); err != nil {
		m.t.Fatalf("failed to write file: %s", err)
	}
}

func (m *mockSlack) checkcookie(w http.ResponseWriter, r *http.Request) {
	if m.checkcookieFail {
		http.Error(w, "request configured to fail", http.StatusInternalServerError)
		return
	}

	if !cookieValid(tdStartSessionCookieName, tdStartSessionCookieValue, r) {
		fmt.Fprint(w, "BAD COOKIE OR NO COOKIE PRESENT")
		return
	}

	redir := r.FormValue("redir")

	if len(redir) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "redir QUERY PARAM NOT PRESENT")
		return
	}

	http.Redirect(w, r, "http://"+r.Host+"/", http.StatusFound)
}

func muxStartSession(t *testing.T, m *mockSlack) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", getpostmw(t, m.root))
	mux.HandleFunc("/messages", getmw(m.messages))
	mux.HandleFunc("/checkcookie", getmw(m.checkcookie))

	return mux
}
