// Copyright 2013 macaron Authors
// Copyright 2016 The Macaron Authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package oauth2_test

import (
	"testing"

	"github.com/go-macaron/oauth2"
	"github.com/go-macaron/session"
	goauth2 "golang.org/x/oauth2"
	"gopkg.in/macaron.v1"
)

// TODO(jbd): Remove after Go 1.4.
// Related to https://codereview.appspot.com/107320046
func TestA(t *testing.T) {}

func ExampleLogin() {
	m := macaron.Classic()
	m.Use(session.Sessioner())
	m.Use(oauth2.Google(
		&goauth2.Config{
			ClientID:     "client_id",
			ClientSecret: "client_secret",
			Scopes:       []string{"https://www.googleapis.com/auth/drive"},
			RedirectURL:  "redirect_url",
		},
	))

	// Tokens are injected to the handlers
	m.Get("/", func(tokens oauth2.Tokens) string {
		if tokens.Expired() {
			return "not logged in, or the access token is expired"
		}
		return "logged in"
	})

	// Routes that require a logged in user
	// can be protected with oauth2.LoginRequired handler.
	// If the user is not authenticated, they will be
	// redirected to the login path.
	m.Get("/restrict", oauth2.LoginRequired, func(tokens oauth2.Tokens) string {
		return tokens.Access()
	})

	m.Run()
}
