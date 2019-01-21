package slackmech

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/pkg/errors"
)

const invitesPath = "/admin/invites"

const (
	invitesCrumb   = `boot_data.crumb_key = "crumb=`
	invitesPending = `boot_data.pending_invites = `

	invitesActionResend = "resend"
	invitesActionRevoke = "revoke"
)

// InvitePref are the invite preferences as provided by the user.
type InvitePref struct {
	DomainMatch bool   `json:"domain_match"`
	RealName    string `json:"real_name"`
}

// InvitePrefs is a special type to contain the invite preferences for a user's
// invite. In some cases Slack returns an Array for this instead of an object,
// which creates challenges for the default decoder. This type exists to gracefully handle either case.
type InvitePrefs []InvitePref

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (i *InvitePrefs) UnmarshalJSON(b []byte) error {
	var ip InvitePref
	if err := json.Unmarshal(b, &ip); err != nil {
		var ips []InvitePref

		if err = json.Unmarshal(b, &ips); err != nil {
			return err
		}

		if len(ips) > 1 {
			ips = ips[:1]
		}

		*i = ips

		return nil
	}

	*i = InvitePrefs{ip}

	return nil
}

// Invite represents the single invite for a user.
type Invite struct {
	ID          int64       `json:"id"`
	Email       string      `json:"email"`
	DateCreate  int64       `json:"date_create"`
	DateResent  int64       `json:"date_resent"`
	Bouncing    bool        `json:"bouncing"`
	InvitePrefs InvitePrefs `json:"invite_prefs"`
}

func (c *Client) getInvites() (*http.Response, error) {
	url := c.endpoint + invitesPath

	resp, err := c.get(url, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if resp.StatusCode != 200 {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, errors.Errorf("GET %q unexpected status: %s", url, resp.Status)
	}

	return resp, nil
}

// PendingInvites retrieves the list of currently pending invites.
func (c *Client) PendingInvites() ([]Invite, string, error) {
	resp, err := c.getInvites()
	if err != nil {
		return nil, "", err
	}

	defer func() { _ = resp.Body.Close() }()

	// at the time of implementation, with ~2300 oustanding invites, this
	// generates a payload that's ~12.20MB in size.
	//
	// we're gonna need a bigger boat
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to read resp.Body")
	}

	crumb, err := parseInlineJsValue(body, invitesCrumb, '"')
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to extract crumb")
	}

	invites, err := extractPendingInvites(body)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to extract invites")
	}

	return invites, crumb, nil
}

func extractPendingInvitesJSON(b []byte) ([]byte, error) {
	if i := bytes.Index(b, []byte(invitesPending)); i > -1 {
		start := i + len(invitesCrumb) - 1

		if e := bytes.IndexByte(b[start:], '\n'); e > -1 {
			if f := bytes.LastIndexByte(b[start:start+e], ';'); f > -1 {
				return b[start : start+f], nil
			}

			return nil, errors.Errorf("could not find terminating ';' after index %d", start)
		}

		return nil, errors.Errorf(`could not find terminating '\n' after index %d`, start)
	}

	return nil, errors.Errorf("failed to find '%s' within input", invitesCrumb)
}

func extractPendingInvites(b []byte) ([]Invite, error) {
	j, err := extractPendingInvitesJSON(b)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract JSON")
	}

	var invites []Invite

	if err = json.Unmarshal(j, &invites); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JSON")
	}

	return invites, nil
}

// ResendInvites is a function to resend 1...n invites from Slack. The first
// argument is the CSRF token (crumb) provided by the PendingInvites() function.
// If you don't have one, using "" will result in this function retrieving one.
// You then provide the invitation IDs to resend as the second (variadic)
// argument. Providing zero IDs to resend is an error.
func (c *Client) ResendInvites(crumb string, resendIDs ...int64) (string, error) {
	return c.actionInvites(invitesActionResend, crumb, resendIDs...)
}

// RevokeInvites is a function to revoke 1...n invites from Slack. The first
// argument is the CSRF token (crumb) provided by the PendingInvites() function.
// If you don't have one, using "" will result in this function retrieving one.
// You then provide the invitation IDs to revoke as the second (variadic)
// argument. Providing zero IDs to revoke is an error.
func (c *Client) RevokeInvites(crumb string, revokeIDs ...int64) (string, error) {
	return c.actionInvites(invitesActionRevoke, crumb, revokeIDs...)
}

// actionInvites revokes or resends the invites based on the action provided. It
// uses the provided crumb as the initial, and returns any errors. It also
// returns the next crumb to be used for any following requests. If the action
// is not resend or revoke it returns an error.
func (c *Client) actionInvites(action, crumb string, ids ...int64) (string, error) {
	if action != "revoke" && action != "resend" {
		return "", errors.Errorf("unknown action %q, valid actions: resend,revoke", action)
	}

	if len(ids) < 1 {
		return "", errors.New("must provide more than 0 invitation IDs")
	}

	if crumb == "" {
		resp, err := c.getInvites()
		if err != nil {
			return "", errors.Wrap(err, "failed to get initial crumb")
		}

		// XXX(theckman): limit read to 200KB
		//
		// in testing the data we wanted was within 100KB, but try to make this
		// a little less brittle if Slack changes their HTML output
		buf := make([]byte, 200*1024)

		n, err := io.ReadFull(resp.Body, buf)
		if err != nil && err != io.ErrUnexpectedEOF { // short reads: maybe ok
			return "", errors.Wrap(err, "failed to read response body")
		}

		buf = buf[:n]

		// blank identifier to make errcheck happy
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()

		crumb, err = parseInlineJsValue(buf, invitesCrumb, '"')
		if err != nil {
			return "", errors.Wrap(err, "failed to extract crumb from response body")
		}

		if len(crumb) == 0 { // something funky happened
			return "", errors.Errorf("c.getInvites() output produced no crumb and no error")
		}
	}

	var err error

	for _, id := range ids {
		if crumb, err = c.actionInvite(action, crumb, id); err != nil {
			return "", errors.Wrapf(err, "failed to revoke invite %d", id)
		}
	}

	return crumb, nil
}

// actionInvite revokes or resends an invite based on the action provided. It
// uses the provided crumb, and returns any errors. It also returns the next
// crumb to be used for any following requests. This function does not validate
// whether action is valid and is left up to the caller.
func (c *Client) actionInvite(action, crumb string, id int64) (string, error) {
	urlStr := c.endpoint + invitesPath

	v := url.Values{
		action:  []string{strconv.FormatInt(id, 10)},
		"crumb": []string{crumb},
	}

	resp, err := c.get(urlStr, v)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", errors.Errorf("unexpected status code for GET '%s?%s': %s", urlStr, v.Encode(), resp.Status)
	}

	// written this way to appease errcheck
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// XXX(theckman): limit read to 200KB
	//
	// in testing the data we wanted was within 100KB, but try to make this
	// a little less brittle if Slack changes their HTML output
	buf := make([]byte, 200*1024)

	n, err := io.ReadFull(resp.Body, buf)
	if err != nil && err != io.ErrUnexpectedEOF { // short reads: maybe ok
		return "", errors.Wrap(err, "failed to read response body")
	}

	buf = buf[:n]

	crumb, err = parseInlineJsValue(buf, invitesCrumb, '"')
	if err != nil {
		return "", errors.Wrap(err, "failed to extract crumb from response body")
	}

	return crumb, nil
}
