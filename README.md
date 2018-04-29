# slackmech
[![License](https://img.shields.io/github/license/theckman/slackmech.svg)](https://github.com/theckman/slackmech/blob/master/LICENSE)
[![GoDoc Page](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/theckman/slackmech)
[![Latest Git Tag](https://img.shields.io/github/tag/theckman/slackmech.svg)](https://github.com/theckman/slackmech/releases)
[![TravisCI master Branch Build Status](https://img.shields.io/travis/theckman/slackmech/master.svg)](https://travis-ci.org/theckman/slackmech/branches)
[![Go Cover Test Coverage](https://gocover.io/_badge/github.com/theckman/slackmech?v0)](https://gocover.io/github.com/theckman/slackmech)
[![Go Report Card](https://goreportcard.com/badge/github.com/theckman/slackmech)](https://goreportcard.com/report/github.com/theckman/slackmech)

Package `slackmech` is a package for mechanizing requests to the Slack API. It
helps imitate a web session with Slack, to present you with a session API token.
This token has different API access, including undocumented behaviors, to allow
special features of the Web/Electron UI. This package will also abstract away
some of those API calls, making it easier to consume them.

As of now, the features of this project are focused towards a bot for moderating
Open Source Slack communities. Things will be added as they are needed to
support that effort, or as contributions from others are made.

This package is still under active development.

### Compatibility Notice
The behaviors and functions relied on by this package are largely undocumented,
and the usage of them fall outside of any compatibility guarantees provided by
Slack. While the functionality provided by this package is necessary, it's
reasonable to assume it may break unexpectedly in the future.

As such, at the time of writing, it seems unlikely that this package will ever
be able to see a 1.0.0 release. However, efforts will be made to retain API
compatibility as long as possible. The package will have releases, using git
tags, following the [Semantic Version v2.0.0 spec](https://semver.org/spec/v2.0.0.html).

## License
This source code of this package is released under the MIT License. Please see
the [LICENSE](https://github.com/theckman/slackmech/blob/master/LICENSE) for the
full content of the license.

## Usage
To be a respectful user of the Slack APIs, be sure to use an `*http.Client` with
a cookiejar set, preferably one that makes use of
[persistence](https://github.com/juju/persistent-cookiejar). In our example,
we'll use the standard cookiejar implementation.

Here we'll create a cookiekar, create an HTTP client, create a new slackmech
client, log in, and then use the Session Token to create a new API client:

```Go
import (
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"

	"github.com/nlopes/slack"
	"github.com/theckman/slackmech"

	"golang.org/x/net/publicsuffix"
)

func main() {
	email := os.Getenv("SLACK_EMAIL")
	password := os.Getenv("SLACK_PASSWORD")
	subdomain := os.Getenv("SLACK_SUBDOMAIN")

	cj, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}

	// new http client with cookiejar set
	client := &http.Client{
		Jar: cj,
	}

	// don't follow redirects -- needed by slackmech
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// new slackmech client
	sm, err := slackmech.New(client, subdomain)
	if err != nil {
		log.Fatal(err)
	}

	// log in and get a new session
	err = sm.StartSession(email, password)
	if err != nil {
		log.Fatal(err)
	}

	// use the slackmech SessionToken to build a new Slack API client
	// also pass in the HTTP client used to log in to continue using cookies
	api := slack.New(sm.SessionToken(), slack.OptionHTTPClient(client))
}
```
