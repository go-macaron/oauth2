// Copyright 2014 Google Inc. All Rights Reserved.
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

// Package oauth2 contains Macaron handlers to provide user login via an OAuth 2.0 backend.
package oauth2

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/go-macaron/session"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/macaron.v1"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/linkedin"
)

const (
	KEY_TOKEN     = "oauth2_token"
	KEY_NEXT_PAGE = "next"
)

var (
	// PathLogin is the path to handle OAuth 2.0 logins.
	PathLogin = "/login"
	// PathLogout is the path to handle OAuth 2.0 logouts.
	PathLogout = "/logout"
	// PathCallback is the path to handle callback from OAuth 2.0 backend
	// to exchange credentials.
	PathCallback = "/oauth2callback"
	// PathError is the path to handle error cases.
	PathError = "/oauth2error"
)

// Tokens represents a container that contains user's OAuth 2.0 access and refresh tokens.
type Tokens interface {
	Access() string
	Refresh() string
	Expired() bool
	ExpiryTime() time.Time
}

type token struct {
	oauth2.Token
}

// Access returns the access token.
func (t *token) Access() string {
	return t.AccessToken
}

// Refresh returns the refresh token.
func (t *token) Refresh() string {
	return t.RefreshToken
}

// Expired returns whether the access token is expired or not.
func (t *token) Expired() bool {
	if t == nil {
		return true
	}
	return !t.Token.Valid()
}

// ExpiryTime returns the expiry time of the user's access token.
func (t *token) ExpiryTime() time.Time {
	return t.Expiry
}

// String returns the string representation of the token.
func (t *token) String() string {
	return fmt.Sprintf("tokens: %v", t)
}

// Google returns a new Google OAuth 2.0 backend endpoint.
func Google(conf *oauth2.Config) macaron.Handler {
	conf.Endpoint = google.Endpoint
	return NewOAuth2Provider(conf)
}

// Github returns a new Github OAuth 2.0 backend endpoint.
func Github(conf *oauth2.Config) macaron.Handler {
	conf.Endpoint = github.Endpoint
	return NewOAuth2Provider(conf)
}

// Facebook returns a new Facebook OAuth 2.0 backend endpoint.
func Facebook(conf *oauth2.Config) macaron.Handler {
	conf.Endpoint = facebook.Endpoint
	return NewOAuth2Provider(conf)
}

// LinkedIn returns a new LinkedIn OAuth 2.0 backend endpoint.
func LinkedIn(conf *oauth2.Config) macaron.Handler {
	conf.Endpoint = linkedin.Endpoint
	return NewOAuth2Provider(conf)
}

// NewOAuth2Provider returns a generic OAuth 2.0 backend endpoint.
func NewOAuth2Provider(conf *oauth2.Config) macaron.Handler {
	return func(s session.Store, ctx *macaron.Context) {
		if ctx.Req.Method == "GET" {
			switch ctx.Req.URL.Path {
			case PathLogin:
				login(conf, ctx, s)
			case PathLogout:
				logout(ctx, s)
			case PathCallback:
				handleOAuth2Callback(conf, ctx, s)
			}
		}
		tk := unmarshallToken(s)
		if tk != nil {
			// check if the access token is expired
			if tk.Expired() && tk.Refresh() == "" {
				s.Delete(KEY_TOKEN)
				tk = nil
			}
		}
		// Inject tokens.
		ctx.MapTo(tk, (*Tokens)(nil))
	}
}

// Handler that redirects user to the login page
// if user is not logged in.
// Sample usage:
// m.Get("/login-required", oauth2.LoginRequired, func() ... {})
var LoginRequired = func() macaron.Handler {
	return func(s session.Store, ctx *macaron.Context) {
		token := unmarshallToken(s)
		if token == nil || token.Expired() {
			next := url.QueryEscape(ctx.Req.URL.RequestURI())
			ctx.Redirect(PathLogin + "?next=" + next)
		}
	}
}()

func login(f *oauth2.Config, ctx *macaron.Context, s session.Store) {
	next := extractPath(ctx.Req.URL.Query().Get(KEY_NEXT_PAGE))
	if s.Get(KEY_TOKEN) == nil {
		// User is not logged in.
		if next == "" {
			next = "/"
		}
		ctx.Redirect(f.AuthCodeURL(next))
		return
	}
	// No need to login, redirect to the next page.
	ctx.Redirect(next)
}

func logout(ctx *macaron.Context, s session.Store) {
	next := extractPath(ctx.Req.URL.Query().Get(KEY_NEXT_PAGE))
	s.Delete(KEY_TOKEN)
	ctx.Redirect(next)
}

func handleOAuth2Callback(f *oauth2.Config, ctx *macaron.Context, s session.Store) {
	next := extractPath(ctx.Req.URL.Query().Get("state"))
	code := ctx.Req.URL.Query().Get("code")
	t, err := f.Exchange(oauth2.NoContext, code)
	if err != nil {
		// Pass the error message, or allow dev to provide its own
		// error handler.
		ctx.Redirect(PathError)
		return
	}
	// Store the credentials in the session.
	val, _ := json.Marshal(t)
	s.Set(KEY_TOKEN, val)
	ctx.Redirect(next)
}

func unmarshallToken(s session.Store) (t *token) {
	if s.Get(KEY_TOKEN) == nil {
		return
	}
	data := s.Get(KEY_TOKEN).([]byte)
	var tk oauth2.Token
	json.Unmarshal(data, &tk)
	return &token{tk}
}

func extractPath(next string) string {
	n, err := url.Parse(next)
	if err != nil {
		return "/"
	}
	return n.Path
}
