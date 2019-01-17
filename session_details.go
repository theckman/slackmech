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
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

const (
	apiTokenString   = `api_token: "` /* #nosec */
	logOutURLString  = `boot_data.logout_url = "`
	versionTSstring  = `version_ts: "`
	versionUIDstring = `version_uid: "`
)

type sessionDetails struct {
	sessionToken string
	versionTS    string
	versionUID   string
	logOutURL    string
}

func (c *Client) getSessionDetails() (sessionDetails, error) {
	url := c.endpoint + "/messages"

	resp, err := c.get(url, nil)
	if err != nil {
		return sessionDetails{}, errors.Wrapf(err, "failed to get %q", url)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return sessionDetails{}, errors.Errorf("unexpected HTTP response status: %s", resp.Status)
	}

	return parseSessionDetails(resp.Body)
}

// parseInlineJsValue assumes you're pulling a string value from a byte slice that
// contains JavaScript objects. The search string would be something like
// `api_token: "` to search for the beginning of the value we want to parse out.
//
// This function then finds the location of the end byte, relative to the end of
// the search string. This effectively will extract whatever is between the last
// byte of `search` and the `end` byte, returning it to the caller as a string.
func parseInlineJsValue(p []byte, search string, end byte) (string, error) {
	// get the index of the search value
	i := bytes.Index(p, []byte(search))
	if i < 0 {
		return "", errors.Errorf("%q not found in byte slice", search)
	}

	// b is the index of the beginning of the value we want
	b := i + len(search)

	// get the index of the next double quote character, starting from b
	ii := bytes.IndexByte(p[b:], end)
	if ii < 0 {
		return "", errors.Errorf("did not find terminating byte (%q) in input", end)
	}

	// e is the subslice index of the end of the value we want)
	e := b + ii // the end

	return string(p[b:e]), nil
}

func parseSessionDetails(r io.Reader) (sessionDetails, error) {
	// XXX(theckman): the session details we need to mechanize requests
	// (api_token) is injected in to the HTML response body of the "/messages"
	// resource at some location.
	//
	// We use ReadAll because we aren't sure where, in the response, the content
	// is that we want. If we had a better idea, we could use a more
	// appropriately sized buffer instead of streaming the entire response in to
	// memory.
	p, err := ioutil.ReadAll(r)
	if err != nil {
		return sessionDetails{}, errors.Wrap(err, "failed to read response")
	}

	if len(p) <= len(apiTokenString) {
		return sessionDetails{}, errors.New("input too short to contain valid data")
	}

	// look for the api_token value within the response body buffer
	apiToken, err := parseInlineJsValue(p, apiTokenString, '"')
	if err != nil {
		return sessionDetails{}, errors.New("unable to find api_token in response")
	}

	// look for the version_ts value within the response body buffer
	versionTS, err := parseInlineJsValue(p, versionTSstring, '"')
	if err != nil {
		return sessionDetails{}, errors.New("unable to find version_ts in response")
	}

	// look for the version_uid value within the response body buffer
	versionUID, err := parseInlineJsValue(p, versionUIDstring, '"')
	if err != nil {
		return sessionDetails{}, errors.New("unable to find version_uid in response")
	}

	// get the logoutURL value; while noting its format is different than those above
	// because of this format difference we also need to do some later string formatting
	logoutURL, err := parseInlineJsValue(p, logOutURLString, ';')
	if err != nil {
		return sessionDetails{}, errors.New("unable to find boot_data.logout_url in response")
	}

	// clean up the string to only be the URL and not other parts
	logoutURL = formatLogoutURL(logoutURL)

	// try to confirm that the logoutURL has been properly formatted
	if _, err := url.Parse(logoutURL); err != nil {
		return sessionDetails{}, errors.Wrapf(err, "failed to validate logoutURL (%q) after formatting", logoutURL)
	}

	sd := sessionDetails{
		sessionToken: apiToken,
		versionTS:    versionTS,
		versionUID:   versionUID,
		logOutURL:    logoutURL,
	}

	return sd, nil
}

// logoutURLreplacer is meant to help clean up the logout URL provided within
// the inline JavaScript. See the formatLogoutURL function for more details
// around why we need this.
var logoutURLreplacer = strings.NewReplacer(`"`, "", `'`, "", `+`, "")

// formatLogoutURL takes the logout URL string as presented in the response
// body, and cleans it up. This function expects the JavaScript prefix
// (boot_data.logout_url = ") has been stripped, and that the delimiting
// character (;) is also removed from the end. This results in a string that
// looks something like
//
// 		https:\/\/slack.com\/"+'signout/'+"7331842483"+'?crumb=s-1523212012-e051261e2dc00d007973fd19eb3497d45fbe4432dee2b2121d35afa72a5d7af1-%E2%98%83'
//
// We then need to replace things like `"` with an empty string, as well as the
// other symbols presenting this from being a valid URL. Lastly, we need to
// replace the escaped slashes to make this a valid URL.
func formatLogoutURL(s string) string {
	return strings.Replace(logoutURLreplacer.Replace(s), `\/`, "/", -1)
}
