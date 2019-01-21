package slackmech

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
)

const (
	tdPendingInvites                 = "./testdata/pending_invites.html"
	tdPendingInvitesAltCrumb         = "./testdata/pending_invites_alt_crumb.html"
	tdPendingInvitesMissingNewline   = "./testdata/pending_invites_missing_newline.html"
	tdPendingInvitesMissingSemicolon = "./testdata/pending_invites_missing_semicolon.html"
	tdPendingInvitesNoCrumb          = "./testdata/pending_invites_no_crumb.html"
	tdPendingInvitesEmptyPending     = "./testdata/pending_invites_empty_pending.html"
	tdPendingInvitesNoPending        = "./testdata/pending_invites_no_pending.html"
	tdPendingInvitesMalformedJSON    = "./testdata/pending_invites_malformed_json.html"

	tvPendingInvitesCrumb    = `s-1547620885-REDACTED-☃`
	tvPendingInvitesCrumbAlt = `s-1547620885-ALTERNATE-☃`
	tvPendingInvitesJSON     = `[{"id":1,"email":"REDACTED","date_create":1547610040,"date_resent":0,"bouncing":true,"invite_prefs":{"domain_match":true,"real_name":"REDACTED"},"inviter":{"id":"U0J66UKPG","team_id":"T029RQSE6","name":"gophers","deleted":false,"color":"4ec0d6","real_name":"Gophers Admins","tz":"America/Los_Angeles","tz_label":"Pacific Standard Time","tz_offset":-28800,"profile":{"real_name":"Gophers Admins","display_name":"gophers","email":"REDACTED","team":"T029RQSE6"},"is_admin":true,"is_owner":false,"is_primary_owner":false,"is_restricted":false,"is_ultra_restricted":false,"is_bot":false,"is_app_user":false,"updated":1504133953,"has_2fa":false}},{"id":42,"email":"REDACTED","date_create":1547610041,"date_resent":0,"bouncing":false,"invite_prefs":{"domain_match":false,"real_name":"REDACTED"},"inviter":{"id":"U0J66UKPG","team_id":"T029RQSE6","name":"gophers","deleted":false,"color":"4ec0d6","real_name":"Gophers Admins","tz":"America/Los_Angeles","tz_label":"Pacific Standard Time","tz_offset":-28800,"profile":{"real_name":"Gophers Admins","display_name":"gophers","email":"REDACTED","team":"T029RQSE6"},"is_admin":true,"is_owner":false,"is_primary_owner":false,"is_restricted":false,"is_ultra_restricted":false,"is_bot":false,"is_app_user":false,"updated":1504133953,"has_2fa":false}}]`
)

var tvPendingInvites = []Invite{
	{
		ID:         1,
		Email:      "REDACTED",
		DateCreate: 1547610040,
		DateResent: 0,
		Bouncing:   true,
		InvitePrefs: InvitePrefs{
			InvitePref{
				DomainMatch: true,
				RealName:    "REDACTED",
			},
		},
	},
	{
		ID:         42,
		Email:      "REDACTED",
		DateCreate: 1547610041,
		DateResent: 0,
		Bouncing:   false,
		InvitePrefs: InvitePrefs{
			InvitePref{
				DomainMatch: false,
				RealName:    "REDACTED",
			},
		},
	},
}

func TestInvitePrefs_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		n string
		i string
		e string
		p *InvitePrefs
	}{
		{
			n: "single_object",
			i: `{"domain_match":true,"real_name":"urmom"}`,
			p: &InvitePrefs{InvitePref{
				DomainMatch: true,
				RealName:    "urmom",
			}},
		},
		{
			n: "array_one_object",
			i: `[{"domain_match":true,"real_name":"urmom"}]`,
			p: &InvitePrefs{InvitePref{
				DomainMatch: true,
				RealName:    "urmom",
			}},
		},
		{
			n: "array_two_objects",
			i: `[{"domain_match":true,"real_name":"urmom"},{"domain_match":true,"real_name":"urmom2"}]`,
			p: &InvitePrefs{InvitePref{
				DomainMatch: true,
				RealName:    "urmom",
			}},
		},
		{
			n: "array_empty",
			i: `[]`,
			p: &InvitePrefs{},
		},
		{
			n: "invalid_json",
			i: `{`,
			e: "unexpected end of JSON input",
		},
	}

	for _, tt := range tests {
		var err error
		t.Run(tt.n, func(t *testing.T) {
			ip := &InvitePrefs{}

			err = ip.UnmarshalJSON([]byte(tt.i))
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

			if diff := cmp.Diff(ip, tt.p); diff != "" {
				t.Errorf("InvitePrefs differs: (-want +got)\n%s", diff)
			}
		})
	}
}

func Test_extractPendingInvitesJSON(t *testing.T) {
	tests := []struct {
		n string
		f string
		e string
		b []byte
	}{
		{
			n: "happy_path",
			f: tdPendingInvites,
			b: []byte(tvPendingInvitesJSON),
		},
		{
			n: "missing_newline",
			f: tdPendingInvitesMissingNewline,
			e: `could not find terminating '\n' after index 158`,
		},
		{
			n: "missing_semicolon",
			f: tdPendingInvitesMissingSemicolon,
			e: `could not find terminating ';' after index 158`,
		},
		{
			n: "missing_start",
			f: tdPendingInvitesNoPending,
			e: `failed to find 'boot_data.crumb_key = "crumb=' within input`,
		},
	}

	for _, tt := range tests {
		var input, res []byte
		var err error

		t.Run(tt.n, func(t *testing.T) {
			input, err = ioutil.ReadFile(tt.f)
			if err != nil {
				t.Fatalf("unexpected error reading %q: %v", tt.f, err)
			}

			res, err = extractPendingInvitesJSON(input)
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("extractPendingInvitesJSON() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if diff := cmp.Diff(res, tt.b); diff != "" {
				t.Errorf("JSON output differs: (-want +got)\n%s", diff)
			}
		})
	}
}

func Test_extractPendingInvites(t *testing.T) {
	tests := []struct {
		n string
		f string
		e string
		i []Invite
	}{
		{
			n: "missing_semicolon",
			f: tdPendingInvitesMissingSemicolon,
			e: "failed to extract JSON: could not find terminating ';' after index 158",
		},
		{
			n: "malformed_json",
			f: tdPendingInvitesMalformedJSON,
			e: "failed to unmarshal JSON: unexpected end of JSON input",
		},
		{
			n: "pending_invites_empty",
			f: tdPendingInvitesEmptyPending,
			i: []Invite{},
		},
		{
			n: "happy_path",
			f: tdPendingInvites,
			i: tvPendingInvites,
		},
	}

	for _, tt := range tests {
		var input []byte
		var res []Invite
		var err error

		t.Run(tt.n, func(t *testing.T) {
			input, err = ioutil.ReadFile(tt.f)
			if err != nil {
				t.Fatalf("unexpected error reading %q: %v", tt.f, err)
			}

			res, err = extractPendingInvites(input)
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("extractPendingInvitesJSON() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if diff := cmp.Diff(res, tt.i); diff != "" {
				t.Errorf("Invite slice differs: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestClient_getInvites(t *testing.T) {
	mux := muxPendingInvites(t)

	https := httptest.NewServer(mux)

	httpc := newTestHTTPClient(nil)

	c := &Client{
		c: httpc,
	}

	tests := []struct {
		n        string
		endpoint string
		e        string
	}{
		{
			n:        "connection_error",
			endpoint: "http://192.0.2.1",
			e:        "Get http://192.0.2.1/admin/invites: dial tcp 192.0.2.1:80: i/o timeout",
		},
		{
			n:        "bad_status_code",
			endpoint: https.URL + "/bsc",
			e:        `" unexpected status: 503 Service Unavailable`,
		},
		{
			n:        "happy_path",
			endpoint: https.URL,
		},
	}

	for _, tt := range tests {
		var resp *http.Response
		var err error

		t.Run(tt.n, func(t *testing.T) {
			c.endpoint = tt.endpoint

			resp, err = c.getInvites()
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("extractPendingInvitesJSON() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read all of request body: %v", err)
			}

			if !bytes.Contains(b, []byte(tvPendingInvitesJSON)) {
				t.Fatal("did not find pending_invites JSON in resp.Body")
			}
		})
	}
}

func TestClient_PendingInvites(t *testing.T) {
	mux := muxPendingInvites(t)

	https := httptest.NewServer(mux)

	httpc := newTestHTTPClient(nil)

	c := &Client{
		c: httpc,
	}

	tests := []struct {
		n        string
		endpoint string
		e        string
		c        string
		i        []Invite
	}{
		{
			n:        "bad_status_code",
			endpoint: https.URL + "/bsc",
			e:        `" unexpected status: 503 Service Unavailable`,
		},
		{
			n:        "no_crumb",
			endpoint: https.URL + "/nc",
			e:        `failed to extract crumb: 'boot_data.crumb_key = "crumb=' not found in byte slice`,
		},
		{
			n:        "missing_semicolon",
			endpoint: https.URL + "/msc",
			e:        `failed to extract invites: failed to extract JSON: could not find terminating ';' after index 158`,
		},
		{
			n:        "happy_path",
			endpoint: https.URL,
			c:        tvPendingInvitesCrumb,
			i:        tvPendingInvites,
		},
	}

	for _, tt := range tests {
		var invites []Invite
		var crumb string
		var err error

		t.Run(tt.n, func(t *testing.T) {
			c.endpoint = tt.endpoint

			invites, crumb, err = c.PendingInvites()
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("extractPendingInvitesJSON() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if crumb != tt.c {
				t.Errorf("crumb = %q, want %q", crumb, tt.c)
			}

			if diff := cmp.Diff(invites, tt.i); diff != "" {
				t.Errorf("Invite slice differs: (-want +got)\n%s", diff)
			}
		})
	}
}

func TestClient_actionInvite(t *testing.T) {
	var shouldResend, shouldRevoke bool

	mux := muxPendingInvitesValidation(t, generatePendingInvitesValidator(&shouldResend, &shouldRevoke, "42", false))

	https := httptest.NewServer(mux)

	httpc := newTestHTTPClient(nil)

	c := &Client{
		c: httpc,
	}

	tests := []struct {
		n            string
		endpoint     string
		a            string
		shouldResend bool
		shouldRevoke bool
		e            string
		c            string
	}{
		{
			n:        "connection_error",
			endpoint: "http://192.0.2.1",
			a:        invitesActionResend,
			e:        "Get http://192.0.2.1/admin/invites?crumb=s-1547620885-REDACTED-%E2%98%83&resend=42: dial tcp 192.0.2.1:80: i/o timeout",
		},
		{
			n:        "bad_status_code",
			endpoint: https.URL + "/bsc",
			a:        invitesActionResend,
			e:        fmt.Sprintf(`unexpected status code for GET '%s/bsc/admin/invites?crumb=s-1547620885-REDACTED-%%E2%%98%%83&resend=42': 503 Service Unavailable`, https.URL),
		},
		{
			n:            "no_crumb",
			endpoint:     https.URL + "/nc",
			a:            invitesActionRevoke,
			shouldRevoke: true,
			e:            `failed to extract crumb from response body: 'boot_data.crumb_key = "crumb=' not found in byte slice`,
		},
		{
			n:            "happy_path_revoke",
			endpoint:     https.URL,
			a:            invitesActionRevoke,
			shouldRevoke: true,
			c:            tvPendingInvitesCrumbAlt,
		},
		{
			n:            "happy_path_resend",
			endpoint:     https.URL,
			a:            invitesActionResend,
			shouldResend: true,
			c:            tvPendingInvitesCrumbAlt,
		},
	}

	for _, tt := range tests {
		var crumb string
		var err error

		t.Run(tt.n, func(t *testing.T) {
			c.endpoint = tt.endpoint
			shouldResend = tt.shouldResend
			shouldRevoke = tt.shouldRevoke

			crumb, err = c.actionInvite(tt.a, tvPendingInvitesCrumb, 42)
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("extractPendingInvitesJSON() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if crumb != tt.c {
				t.Errorf("crumb = %q, want %q", crumb, tt.c)
			}
		})
	}
}

func TestClient_actionInvites(t *testing.T) {
	var shouldResend, shouldRevoke bool

	mux := muxPendingInvitesValidation(t, generatePendingInvitesValidator(&shouldResend, &shouldRevoke, "", true))

	https := httptest.NewServer(mux)

	httpc := newTestHTTPClient(nil)

	c := &Client{
		c: httpc,
	}

	tests := []struct {
		n            string
		endpoint     string
		a            string
		i            []int64
		ic           string // input crumb
		shouldResend bool
		shouldRevoke bool
		e            string
		oc           string // output crumb
	}{
		{
			n: "invalid_action",
			a: "nonsense value",
			e: `unknown action "nonsense value", valid actions: resend,revoke`,
		},
		{
			n: "invalid_action",
			a: invitesActionRevoke,
			e: "must provide more than 0 invitation IDs",
		},
		{
			n:        "connection_error",
			endpoint: "http://192.0.2.1",
			a:        invitesActionRevoke,
			i:        []int64{1, 42},
			ic:       tvPendingInvitesCrumb,
			e:        "Get http://192.0.2.1/admin/invites?crumb=s-1547620885-REDACTED-%E2%98%83&revoke=1: dial tcp 192.0.2.1:80: i/o timeout",
		},
		{
			n:        "bad_status_code",
			endpoint: https.URL + "/bsc",
			a:        invitesActionRevoke,
			i:        []int64{1, 42},
			ic:       tvPendingInvitesCrumb,
			e:        fmt.Sprintf(`unexpected status code for GET '%s/bsc/admin/invites?crumb=s-1547620885-REDACTED-%%E2%%98%%83&revoke=1': 503 Service Unavailable`, https.URL),
		},
		{
			n:            "no_input_crumb_connection_error",
			endpoint:     "http://192.0.2.1",
			a:            invitesActionRevoke,
			i:            []int64{1, 42},
			shouldRevoke: true,
			e:            "Get http://192.0.2.1/admin/invites: dial tcp 192.0.2.1:80: i/o timeout",
		},
		{
			n:            "no_input_crumb_none_on_page",
			endpoint:     https.URL + "/nc",
			a:            invitesActionRevoke,
			i:            []int64{1, 42},
			shouldRevoke: true,
			e:            `failed to extract crumb from response body: 'boot_data.crumb_key = "crumb=' not found in byte slice`,
		},
		{
			n:        "no_input_crumb_happy_path",
			endpoint: https.URL,
			a:        invitesActionRevoke,
			i:        []int64{1, 42},
			oc:       tvPendingInvitesCrumbAlt,
		},
		{
			n:            "no_crumb",
			endpoint:     https.URL + "/nc",
			a:            invitesActionRevoke,
			i:            []int64{1, 42},
			ic:           tvPendingInvitesCrumb,
			shouldRevoke: true,
			e:            `failed to extract crumb from response body: 'boot_data.crumb_key = "crumb=' not found in byte slice`,
		},
		{
			n:            "happy_path_revoke",
			endpoint:     https.URL,
			a:            invitesActionRevoke,
			i:            []int64{1, 42},
			ic:           tvPendingInvitesCrumb,
			shouldRevoke: true,
			oc:           tvPendingInvitesCrumbAlt,
		},
		{
			n:            "happy_path_resend",
			endpoint:     https.URL,
			a:            invitesActionResend,
			i:            []int64{1, 42},
			ic:           tvPendingInvitesCrumb,
			shouldResend: true,
			oc:           tvPendingInvitesCrumbAlt,
		},
	}

	for _, tt := range tests {
		var crumb string
		var err error

		t.Run(tt.n, func(t *testing.T) {
			c.endpoint = tt.endpoint
			shouldResend = tt.shouldResend
			shouldRevoke = tt.shouldRevoke

			crumb, err = c.actionInvites(tt.a, tt.ic, tt.i...)
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("extractPendingInvitesJSON() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if crumb != tt.oc {
				t.Errorf("crumb = %q, want %q", crumb, tt.oc)
			}
		})
	}
}

func TestClient_ResendInvites(t *testing.T) {
	mux := muxPendingInvitesValidation(t, func(r *http.Request) error {
		if r.Method != http.MethodGet {
			return errors.Errorf("got %s, want %s", r.Method, http.MethodGet)
		}

		if err := r.ParseForm(); err != nil {
			return errors.Wrapf(err, "failed to parse form for request %q", r.URL.String())
		}

		for k := range r.Form {
			if k != "revoke" && k != "resend" && k != "crumb" {
				return errors.Errorf("unknown URL parameter %q: accepts resend,revoke,crumb", k)
			}
		}

		if _, rvok := r.Form["revoke"]; rvok {
			return errors.New("revoke URL parameter should not be present")
		}

		rs, rsok := r.Form["resend"]
		cr, crok := r.Form["crumb"]

		if !rsok {
			return errors.New("revoke URL parameter not present")
		}

		if rsok && !crok {
			return errors.New("revoke URL parameter was present, but not `crumb`")
		}

		if crok && !rsok {
			return errors.New("crumb provided but missing revoke parameter")
		}

		if rsok && len(rs) != 1 {
			return errors.Errorf("revoke URL parameter has unexpected number of values: %d, want 1", len(rs))
		}

		if rsok && (rs[0] != "42" && rs[0] != "1") {
			return errors.Errorf("unknown revoke ID %q", rs[0])
		}

		if crok && len(cr) != 1 {
			return errors.Errorf("crumb URL parameter has unexpected number of values %d, want 1", len(cr))
		}

		if crok && (cr[0] != tvPendingInvitesCrumb && cr[0] != tvPendingInvitesCrumbAlt) {
			return errors.Errorf("unknown crumb %q", cr[0])
		}

		return nil
	})

	https := httptest.NewServer(mux)

	httpc := newTestHTTPClient(nil)

	c := &Client{
		c: httpc,
	}

	tests := []struct {
		n        string
		endpoint string
		i        []int64
		ic       string // input crumb
		e        string
		oc       string // output crumb
	}{
		{
			n:        "connection_error",
			endpoint: "http://192.0.2.1",
			i:        []int64{1, 42},
			ic:       tvPendingInvitesCrumb,
			e:        "Get http://192.0.2.1/admin/invites?crumb=s-1547620885-REDACTED-%E2%98%83&resend=1: dial tcp 192.0.2.1:80: i/o timeout",
		},
		{
			n:        "happy_path",
			endpoint: https.URL,
			i:        []int64{1, 42},
			ic:       tvPendingInvitesCrumb,
			oc:       tvPendingInvitesCrumbAlt,
		},
	}

	for _, tt := range tests {
		var crumb string
		var err error

		t.Run(tt.n, func(t *testing.T) {
			c.endpoint = tt.endpoint

			crumb, err = c.ResendInvites(tt.ic, tt.i...)
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("extractPendingInvitesJSON() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if crumb != tt.oc {
				t.Errorf("crumb = %q, want %q", crumb, tt.oc)
			}
		})
	}
}

func TestClient_RevokeInvites(t *testing.T) {
	mux := muxPendingInvitesValidation(t, func(r *http.Request) error {
		if r.Method != http.MethodGet {
			return errors.Errorf("got %s, want %s", r.Method, http.MethodGet)
		}

		if err := r.ParseForm(); err != nil {
			return errors.Wrapf(err, "failed to parse form for request %q", r.URL.String())
		}

		for k := range r.Form {
			if k != "revoke" && k != "resend" && k != "crumb" {
				return errors.Errorf("unknown URL parameter %q: accepts resend,revoke,crumb", k)
			}
		}

		if _, rsok := r.Form["resend"]; rsok {
			return errors.New("resend URL parameter should not be present")
		}

		rv, rvok := r.Form["revoke"]
		cr, crok := r.Form["crumb"]

		if !rvok {
			return errors.New("revoke URL parameter not present")
		}

		if rvok && !crok {
			return errors.New("revoke URL parameter was present, but not `crumb`")
		}

		if crok && !rvok {
			return errors.New("crumb provided but missing revoke parameter")
		}

		if rvok && len(rv) != 1 {
			return errors.Errorf("revoke URL parameter has unexpected number of values: %d, want 1", len(rv))
		}

		if rvok && (rv[0] != "42" && rv[0] != "1") {
			return errors.Errorf("unknown revoke ID %q", rv[0])
		}

		if crok && len(cr) != 1 {
			return errors.Errorf("crumb URL parameter has unexpected number of values %d, want 1", len(cr))
		}

		if crok && (cr[0] != tvPendingInvitesCrumb && cr[0] != tvPendingInvitesCrumbAlt) {
			return errors.Errorf("unknown crumb %q", cr[0])
		}

		return nil
	})

	https := httptest.NewServer(mux)

	httpc := newTestHTTPClient(nil)

	c := &Client{
		c: httpc,
	}

	tests := []struct {
		n        string
		endpoint string
		i        []int64
		ic       string // input crumb
		e        string
		oc       string // output crumb
	}{
		{
			n:        "connection_error",
			endpoint: "http://192.0.2.1",
			i:        []int64{1, 42},
			ic:       tvPendingInvitesCrumb,
			e:        "Get http://192.0.2.1/admin/invites?crumb=s-1547620885-REDACTED-%E2%98%83&revoke=1: dial tcp 192.0.2.1:80: i/o timeout",
		},
		{
			n:        "happy_path",
			endpoint: https.URL,
			i:        []int64{1, 42},
			ic:       tvPendingInvitesCrumb,
			oc:       tvPendingInvitesCrumbAlt,
		},
	}

	for _, tt := range tests {
		var crumb string
		var err error

		t.Run(tt.n, func(t *testing.T) {
			c.endpoint = tt.endpoint

			crumb, err = c.RevokeInvites(tt.ic, tt.i...)
			if err != nil {
				if len(tt.e) > 0 {
					if strings.Contains(err.Error(), tt.e) {
						return
					}
					t.Fatalf("did not find %q in error %q", tt.e, err)
				}
				t.Fatalf("extractPendingInvitesJSON() unexpected error: %s", err)
			}

			if len(tt.e) > 0 {
				t.Fatalf("error %q did not occur as expected", tt.e)
			}

			if crumb != tt.oc {
				t.Errorf("crumb = %q, want %q", crumb, tt.oc)
			}
		})
	}
}

func muxPendingInvites(t *testing.T) *http.ServeMux {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/bsc/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "SHOULD CAUSE ERROR")
	})

	mux.HandleFunc("/nc/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(tdPendingInvitesNoCrumb)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error opening %q: %v", tdPendingInvitesNoCrumb, err)
			t.Errorf("failed to open file %q in HTTP handler: %v", tdPendingInvitesNoCrumb, err)
			return
		}

		defer func() { _ = f.Close() }()

		_, _ = io.Copy(w, f)
	})

	mux.HandleFunc("/msc/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(tdPendingInvitesMissingSemicolon)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error opening %q: %v", tdPendingInvitesMissingSemicolon, err)
			t.Errorf("failed to open file %q in HTTP handler: %v", tdPendingInvitesMissingSemicolon, err)
			return
		}

		defer func() { _ = f.Close() }()

		_, _ = io.Copy(w, f)
	})

	mux.HandleFunc("/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(tdPendingInvites)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error opening %q: %v", tdPendingInvites, err)
			t.Errorf("failure to open file %q in HTTP handler: %v", tdPendingInvites, err)
			return
		}

		defer func() { _ = f.Close() }()

		_, _ = io.Copy(w, f)
	})

	return mux
}

func muxPendingInvitesValidation(t *testing.T, validation func(*http.Request) error) *http.ServeMux {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/bsc/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "SHOULD CAUSE ERROR")
	})

	mux.HandleFunc("/nc/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(tdPendingInvitesNoCrumb)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error opening %q: %v", tdPendingInvitesNoCrumb, err)
			t.Errorf("failed to open file %q in HTTP handler: %v", tdPendingInvitesNoCrumb, err)
			return
		}

		defer func() { _ = f.Close() }()

		_, _ = io.Copy(w, f)
	})

	mux.HandleFunc("/admin/invites", func(w http.ResponseWriter, r *http.Request) {
		if validation != nil {
			if err := validation(r); err != nil {
				w.WriteHeader(http.StatusUnprocessableEntity)
				fmt.Fprintf(w, "validation failed %q: %v", tdPendingInvites, err)
				t.Errorf("validation of GET request %q failed: %v", r.URL.String(), err)
				return
			}
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error parsing form(s): %v", err)
			t.Errorf("failed to parse form(s): %v", err)
			return
		}

		_, rv := r.Form["revoke"]
		_, rs := r.Form["resend"]

		var filename string

		if !rv && !rs {
			filename = tdPendingInvites
		} else {
			filename = tdPendingInvitesAltCrumb
		}

		f, err := os.Open(filename) /* #nosec */
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error opening %q: %v", filename, err)
			t.Errorf("failure to open file %q in HTTP handler: %v", filename, err)
			return
		}

		defer func() { _ = f.Close() }()

		_, _ = io.Copy(w, f)
	})

	return mux
}

func generatePendingInvitesValidator(shouldResend, shouldRevoke *bool, expectedID string, allowAlt bool) func(r *http.Request) error {
	return func(r *http.Request) error {
		if r.Method != http.MethodGet {
			return errors.Errorf("got %s, want %s", r.Method, http.MethodGet)
		}

		if err := r.ParseForm(); err != nil {
			return errors.Wrapf(err, "failed to parse form for request %q", r.URL.String())
		}

		for k := range r.Form {
			if k != "revoke" && k != "resend" && k != "crumb" {
				return errors.Errorf("unknown URL parameter %q: accepts resend,revoke,crumb", k)
			}
		}

		rv, rvok := r.Form["revoke"]
		rs, rsok := r.Form["resend"]
		cr, crok := r.Form["crumb"]

		if rvok && rsok {
			return errors.New("both resend and revoke URL parameters provided")
		}

		if rvok && !crok {
			return errors.New("revoke URL parameter was present, but not `crumb`")
		}

		if rsok && !crok {
			return errors.New("resend URL parameter was present, but not `crumb`")
		}

		if crok && (!rvok && !rsok) {
			return errors.New("crumb provided but not action specified (missing revoke or resend parameter)")
		}

		if rvok && len(rv) != 1 {
			return errors.Errorf("revoke URL parameter has unexpected number of values: %d, want 1", len(rv))
		}

		if rvok && ((len(expectedID) > 0 && rv[0] != expectedID) || (rv[0] != "42" && rv[0] != "1")) {
			return errors.Errorf("unknown revoke ID %q", rv[0])
		}

		if rsok && len(rs) != 1 {
			return errors.Errorf("resend URL parameter has unexpected number of values %d, want 1", len(rs))
		}

		if rsok && ((len(expectedID) > 0 && rs[0] != expectedID) || (rs[0] != "42" && rs[0] != "1")) {
			return errors.Errorf("unknown resend ID %q", rs[0])
		}

		if crok && len(cr) != 1 {
			return errors.Errorf("crumb URL parameter has unexpected number of values %d, want 1", len(cr))
		}

		if crok && (cr[0] != tvPendingInvitesCrumb && (allowAlt && cr[0] != tvPendingInvitesCrumbAlt)) {
			return errors.Errorf("unknown crumb %q", cr[0])
		}

		if *shouldResend && !rsok {
			return errors.New("expected resend URL parameter but not found")
		}

		if *shouldRevoke && !rvok {
			return errors.New("expected revoke URL parameter but not found")
		}

		return nil
	}
}
