// Copyright (c) 2018 Tim Heckman
//
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

package slackmech

import (
	"net/http"
	"net/url"
	"strings"
)

func setUA(req *http.Request) {
	req.Header.Set(
		"User-Agent",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:60.0) Gecko/20100101 Firefox/60.0",
	)
}

func getReq(url string, val url.Values) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if len(val) > 0 {
		req.URL.RawQuery = val.Encode()
	}

	setUA(req)

	return req, nil
}

func postFormReq(url string, val url.Values) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(val.Encode()))
	if err != nil {
		return nil, err
	}

	setUA(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}
