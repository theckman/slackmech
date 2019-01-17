// Copyright (c) 2018 Tim Heckman
//
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package slackmech

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// Version is the version of this package.
const Version = "0.1.0"

// loginFailedFlashMessage is a string that is presented when offering incorrect
// credentials during login. This being present is the only way to know the
// difference between invalid credentials and an invalid request.
var loginFailedFlashMessage = []byte(`Sorry, you entered an incorrect email address or password.`)

// HTTPClient represents the functionality we need from an *http.Client, or
// similar.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is a client for making mechanized requests to Slack. The actions this
// client can make are generally unsupported outside of a browser, but they are
// needed to moderate a Slack community. Also, because we are doing something
// that is normally done via a browser, Slack is not expecting a high rate of
// automated calls. Please keep that in mind.
//
// This strut contains a session token that can be used to take API actions as a
// user. This can also be used with the Slack API library
// (github.com/nlopes/slack) to communicate with users in real time.
//
// When calling the constructor, you must provide an `*http.Client` with a
// cookiejar configured. It's recommended you use one with persistence, to avoid
// your client causing problem for Slack by requiring a log in on each process
// start.
type Client struct {
	logOutURL    string
	sessionToken string
	versionTS    string
	versionUID   string

	c        HTTPClient
	endpoint string
}

// New returns a new *Client. After getting the client, you must call
// StartSession to begin an active session. If your provided client already has
// active cookies, call ResumeSession().
//
// The HTTPClient being passed in cannot follow redirects automatically, and
// should instead return the redirect response. This is a requirement for this
// package, or the ability to obtain a new session will be broken.
//
// For an `*http.Client`, this functionality can be turned on by setting the
// `CheckRedirect` field and having it return `http.ErrUseLastResponse`.
func New(c HTTPClient, subdomain string) (*Client, error) {
	if c == nil {
		return nil, errors.New("must provide an http client")
	}

	if len(subdomain) == 0 {
		return nil, errors.New("must provide the Slack workspace subdomain")
	}

	client := &Client{
		c:        c,
		endpoint: "https://" + subdomain + ".slack.com",
	}

	return client, nil
}

func (c *Client) clearSessionDetails() {
	c.logOutURL, c.sessionToken = "", ""
	c.versionTS, c.versionUID = "", ""
}

func (c *Client) get(url string, val url.Values) (*http.Response, error) {
	req, err := getReq(url, val)
	if err != nil {
		return nil, err
	}

	return c.c.Do(req)
}

func (c *Client) postForm(url string, val url.Values) (*http.Response, error) {
	req, err := postFormReq(url, val)
	if err != nil {
		return nil, err
	}

	return c.c.Do(req)
}

func (c *Client) shouldRedirect(url, newLocation string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to build request for %q", url)
	}

	resp, err := c.c.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to make GET request to %q", url)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		return errors.Errorf("%q did not redirect as expected (%s)", url, resp.Status)
	}

	if loc := resp.Header.Get("Location"); loc != newLocation {
		return errors.Errorf("invalid redirect location: want %q, got %q", newLocation, loc)
	}

	return nil
}

// SessionToken returns the session token retrieved from logging in. You can use
// this with the Slack API library (github.com/nlopes/slack).
//
// If you do decide to use the Slack API library, it would be a good idea to use
// the same HTTP client in there as here, in case the cookie used when logging
// in is checked.
func (c *Client) SessionToken() string { return c.sessionToken }

// StartSession starts a new session within the client. This is accomplished by
// logging in to Slack, as if you were a user on the web application, and
// pulling the session token out of the bootstrap data for the JavaScript
// client.
//
// See the internals of this function for a more detailed explanation of how
// this process works.
func (c *Client) StartSession(email, password string) error {
	// The mechanism for logging in to Slack is pretty interesting, and has some
	// checks that I believe were put in place to try and prevent misuse and
	// account hijacking. However, I question their effectiveness beyond
	// creating annoying barriers.
	//
	// The first thing to call out is that Slack does some User-Agent matching
	// in a few areas. It's important to use a Firefox or Chrome User-Agent
	// string, otherwise Slack will render some responses that are missing some
	// data we care about. Using the default Go User-Agent will not work as
	// expected. This was only slightly annoying to track down.
	//
	// To actually log in, the first thing that happens is you need to hit the
	// `/` resource for your Slack group (e.g., https://example.slack.com/). If
	// this responds with a 200, we're not logged in. A 302 (redirect) indicates
	// that we already have a valid cookie (logged in). If we're logged in we
	// can skip to getting the session details from the "/messages" resource.
	//
	// If we are not logged in (200 response), there are a few hidden input
	// fields in response body that should be posted with the sign in request.
	// You can find these in the sign in form. The one required value is that of
	// the "crumb" input field, which looks to be CSRF token that includes the
	// current UNIX epoch, as well as a SHA-512 hash that contains (at a
	// minimum) the current User-Agent string.
	//
	// The fact the crumb value's hash contains the User-Agent string is
	// important. If your User-Agent string changes between getting the "crumb"
	// value and making your log in POST request, Slack will silently refuse to
	// log you in without presenting an error message. This was annoying to
	// track down, so make sure you don't forget to use the same UA string. I
	// presume this is a "security feature" to help obscure the process of
	// trying to log in programmatically, as well as to generally prevent
	// misuse. It wasn't very effective.
	//
	// Once you have the "crumb" value, as well as the others, you can POST them
	// with the "email" and "password" values to the `/` resource for the Slack
	// group. Yes, this is the _same_ resource you got the login form from,
	// except now you're making a POST request instead of a GET request. And
	// yes, make sure you set the Content-Type to "application/x-www-form-urlencoded"
	// or the request will return a 200 with no error message. Props to Slack for
	// doing input validation.
	//
	// If you get a 200 from the POST request, you failed to authenticate/log
	// in. The response body may contain an error indicating the credentials are
	// wrong, or nothing if you sent a malformed request. A malformed request
	// could be that you didn't set the Content-Type, or your User-Agent has
	// changed since getting the "crumb" value (maybe others).
	//
	// If you got a 302 redirect, you've logged in! The first place it sends you
	// to is another endpoint
	// (https://slack.com/checkcookie?redir=YOURWORKSPACE) which validates that
	// your cookie is good, and redirects you to the root of your Slack
	// workgroup if it is indeed good. If the cookie is bad, it renders a page
	// (200 response) that tells you to enable support for cookies.
	//
	// If you've been redirected from the cookiecheck, you're sent to the root
	// of your Slack workspace which should then redirect you to the main
	// resource (/messages). Within the "/messages" HTML response body is the
	// API token we need for interacting with the API as a logged in user, as
	// well as other related pieces of information.
	//
	// From the HTML response body we care about the 'api_token', 'version_ts',
	// 'version_uid', and the 'boot_data.logout_url' inline JavaScript values.
	// We need to parse these values out of the HTML response body, and then we
	// have all of the information we need to have a full session. We also have
	// the URL needed to terminate our session, invalidate the api_token, and
	// delete the cookies.
	//
	// If you make use of the api_token, you can now interact with the Slack API
	// as if you were a logged in webapp user. This comes with certain
	// limitations lifted, depending on your role in the Slack workspace.
	//
	// Okay, now let's get around to the actual implementation...

	// make sure an email and password are set
	if len(email) == 0 || len(password) == 0 {
		return errors.New("both an email and password must be provided")
	}

	// get the login details (hidden form values) for logging in
	// this also tries to check if we're already logged in
	ld, loggedIn, err := c.getLoginDetails()
	if err != nil {
		return err
	}

	// The getLoginDetails() call indicated we are not logged in, so we need to
	// go through the full login workflow. One thing to note, if any of these
	// verification steps result in an HTTP 200 response the process failed.
	// Slack is not redirect adverse.
	if !loggedIn {
		// First we log in with the user's credentials, which is supposed to
		// HTTP 302 redirect us to the checkcookie endpoint. This function
		// returns a path to check the cookie endpoint with the redir query
		// parameter appended.
		checkCookiePath, err := c.logIn(email, password, ld)
		if err != nil {
			return errors.Wrap(err, "failed to log in")
		}

		// The checkcookie endpoint verifies the cookie, and should redirect us
		// back to the Slack workspace's endpoint. If there is no valid cookie,
		// we get served an HTTP 200, which results in an error here.
		if err := c.shouldRedirect(checkCookiePath, c.endpoint+"/"); err != nil {
			return errors.Wrap(err, "cookie validation failed")
		}

		// If the checkcookie endpoint succeeded in redirecting us to the main
		// page (no error above), we can now make sure c.endpoint redirects us
		// to the /messages resource. We must verify this, as our session token
		// is on that page.
		if err := c.shouldRedirect(c.endpoint, "/messages"); err != nil {
			return errors.Wrap(err, "main page to /messages redirect didn't happen")
		}
	}

	// we are logged in, obtain the session details
	sd, err := c.getSessionDetails()
	if err != nil {
		return errors.Wrap(err, "failed to get session details")
	}

	// set the session details
	c.logOutURL = sd.logOutURL
	c.sessionToken = sd.sessionToken
	c.versionTS = sd.versionTS
	c.versionUID = sd.versionUID

	return nil
}

func (c *Client) logIn(email, password string, ld LoginDetails) (string, error) {
	// make sure an email and password are set
	if len(email) == 0 || len(password) == 0 {
		return "", errors.New("both an email and password must be provided")
	}

	// make sure the breadcrumb is provided
	if len(ld.Crumb) == 0 {
		return "", errors.New("LoginDetails must contain a crumb value")
	}

	// make sure the signin value is provided
	if len(ld.Signin) == 0 {
		return "", errors.New("LoginDetails must contain a signin value")
	}

	// make sure the has_remember value is provided
	if len(ld.HasRemember) == 0 {
		return "", errors.New("LoginDetails must contain a has_remember value")
	}

	// build the form data for the login POST request
	v := url.Values{
		"crumb":        []string{ld.Crumb},
		"email":        []string{email},
		"password":     []string{password},
		"redir":        []string{ld.Redir},
		"signin":       []string{ld.Signin},
		"has_remember": []string{ld.HasRemember},
		"remember":     []string{"on"}, // we will not be forgotten
	}

	// post the form data to the login URL
	resp, err := c.postForm(c.endpoint, v)
	if err != nil {
		return "", errors.Wrap(err, "failed to action log in request")
	}

	defer resp.Body.Close()

	// handle the response from the server
	// 302 (Found): log in attempt appears successful; do cookie validation
	// 200 (OK): actually not OK; login failed (wrong creds/missing form data)
	// Other: unexpected response
	switch resp.StatusCode {
	default:
		return "", errors.Errorf("unexpected HTTP response when logging in (%s)", resp.Status)

	case http.StatusFound:
		loc := resp.Header.Get("Location")

		// is the location header the right location, ish?
		if !strings.Contains(loc, "checkcookie") {
			return "", errors.Errorf("unexpected HTTP redirect location header value when logging in (%q)", loc)
		}

		return loc, nil

	case http.StatusOK: // we're actually not OK; login failed
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", errors.Wrap(err, "failed to read response body after unsuccessful log in attempt")
		}

		// look for the flash message Slack provides if the credentials were invalid
		if i := bytes.Index(respBody, loginFailedFlashMessage); i >= 0 {
			return "", errors.Errorf("invalid Slack credentials for %q", c.endpoint)
		}

		return "", errors.Errorf("failed to log in to %q for unknown reason", c.endpoint)
	}
}
