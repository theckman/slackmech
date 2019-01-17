// Copyright (c) 2018 Tim Heckman
//
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package slackmech

import (
	"io"
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// LoginDetails is a struct to contain the hidden fields presented by Slack on
// their login form. Some of these fields are needed for logging in, so this can
// be used to present them back.
type LoginDetails struct {
	Crumb       string
	Redir       string
	Signin      string
	HasRemember string
}

func (c *Client) getLoginDetails() (LoginDetails, bool, error) {
	resp, err := c.get(c.endpoint, nil)
	if err != nil {
		return LoginDetails{}, false, err
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	default:
		return LoginDetails{}, false, errors.Errorf("unexpected HTTP response status: %s", resp.Status)

	case http.StatusOK:
		ld, err := parseLoginDetails(resp.Body)

		// errors.Wrap returns nil if err is nil, otherwise wraps the error
		return ld, false, errors.Wrap(err, "failed retrieve LoginDetails")

	case http.StatusFound:
		loc := resp.Header.Get("Location")

		if loc != "/messages" {
			return LoginDetails{}, false, errors.Errorf("unexpected redirect location: %q", loc)
		}

		// we are already logged in
		// indicate that we should resume session
		return LoginDetails{}, true, nil
	}
}

func parseLoginDetails(r io.Reader) (LoginDetails, error) {
	var ld LoginDetails

	t := html.NewTokenizer(r)

	// loop over the tokenized input to look for an input field with the name
	// attribute "crumb"
	for {
		// get the next token type
		tt := t.Next()

		// if this is an error token we've reached the end
		if tt == html.ErrorToken {
			break
		}

		// we are looking for either the start or self-closing "input" tag
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		// get the full token (tag)
		token := t.Token()

		// if it's not an input tag, move on
		if token.DataAtom != atom.Input {
			continue
		}

		// build a map to track the attributes of this token
		attribs := make(map[string]string, 5)

		// set the attributes
		for _, attr := range token.Attr {
			attribs[attr.Key] = attr.Val
		}

		// based on the tag name, set the right value in the ld struct
		switch attribs["name"] {
		case "crumb":
			ld.Crumb = attribs["value"]
		case "redir":
			ld.Redir = attribs["value"]
		case "signin":
			ld.Signin = attribs["value"]
		case "has_remember":
			ld.HasRemember = attribs["value"]
		default:
			// not a known tag, move on
			continue
		}
	}

	// a crumb is required
	if len(ld.Crumb) == 0 {
		return LoginDetails{}, errors.New("unable to find crumb hidden input in the page")
	}

	return ld, nil
}
