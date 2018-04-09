// Copyright (c) 2018 Tim Heckman
//
// Use of this source code is governed by the MIT License that can be found in
// the LICENSE file at the root of this repository.

// Package slackmech is a package for mechanizing requests to the Slack API. It
// helps imitate a web session with Slack, to present you with a session API
// token. This token has different API access, including undocumented behaviors,
// to allow special features of the Web/Electron UI. This package will also
// abstract away some of those API calls, making it easier to consume them.
//
// As of now, the features of this project are focused towards a bot for
// moderating Open Source Slack communities. Things will be added as they are
// needed to support that effort, or as contributions from others are made.
//
// This package is still under active development.
//
// The behaviors and functions relied on by this package are largely
// undocumented, and the usage of them fall outside of any compatibility
// guarantees provided by Slack. While the functionality provided by this
// package is necessary, it's reasonable to assume it may break unexpectedly in
// the future.
//
// As such, at the time of writing, it seems unlikely that this package will
// ever be able to see a 1.0.0 release. However, efforts will be made to retain
// API compatibility as long as possible. The package will have releases, using
// git tags, following the Semantic Version 2.0.0 spec.
package slackmech
