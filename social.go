// Copyright 2014 Google Inc. All Rights Reserved.
// Copyright 2014 Unknwon
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

package oauth2

// NOTE: last sync 4253789 on Nov 18, 2014.

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/Unknwon/macaron"
	"github.com/macaron-contrib/session"
)

const (
	KEY_TOKEN     = "oauth2_token"
	KEY_NEXT_PAGE = "next"
)

var (
	AppSubUrl string
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
	Extra(string) string
}

// Google returns a new Google OAuth 2.0 backend endpoint.
func Google(opt Options) macaron.Handler {
	return NewOAuth2Provider(opt,
		"https://accounts.google.com/o/oauth2/auth",
		"https://accounts.google.com/o/oauth2/token",
	)
}

// GitHub returns a new Github OAuth 2.0 backend endpoint.
func GitHub(opt Options) macaron.Handler {
	return NewOAuth2Provider(opt,
		"https://github.com/login/oauth/authorize",
		"https://github.com/login/oauth/access_token",
	)
}

func Facebook(opt Options) macaron.Handler {
	return NewOAuth2Provider(opt,
		"https://www.facebook.com/dialog/oauth",
		"https://graph.facebook.com/oauth/access_token",
	)
}

func LinkedIn(opt Options) macaron.Handler {
	return NewOAuth2Provider(opt,
		"https://www.linkedin.com/uas/oauth2/authorization",
		"https://www.linkedin.com/uas/oauth2/accessToken",
	)
}

func Dropbox(opt Options) macaron.Handler {
	return NewOAuth2Provider(opt,
		"https://www.dropbox.com/1/oauth2/authorize",
		"https://api.dropbox.com/1/oauth2/token",
	)
}

func Tencent(opt Options) macaron.Handler {
	return NewOAuth2Provider(opt,
		"https://graph.qq.com/oauth2.0/authorize",
		"https://graph.qq.com/oauth2.0/token",
	)
}

func Weibo(opt Options) macaron.Handler {
	return NewOAuth2Provider(opt,
		"https://api.weibo.com/oauth2/authorize",
		"https://api.weibo.com/oauth2/access_token",
	)
}

func prepareOptions(opt *Options, authURL, tokenURL string) (*Options, error) {
	if len(opt.PathLogin) == 0 {
		opt.PathLogin = PathLogin
	}
	if len(opt.PathLogout) == 0 {
		opt.PathLogout = PathLogout
	}
	if len(opt.PathCallback) == 0 {
		opt.PathCallback = PathCallback
	}
	au, err := url.Parse(authURL)
	if err != nil {
		return nil, err
	}
	tu, err := url.Parse(tokenURL)
	if err != nil {
		return nil, err
	}
	opt.AuthURL = au
	opt.TokenURL = tu
	return opt, nil
}

// NewOAuth2Provider returns a generic OAuth 2.0 backend endpoint.
func NewOAuth2Provider(option Options, authURL, tokenURL string) macaron.Handler {
	opt, err := prepareOptions(&option, authURL, tokenURL)
	if err != nil {
		panic("fail to initialize OAuth2 provider: " + err.Error())
	}

	opt, err = New(opt)
	if err != nil {
		panic("fail to create new OAuth2 provider: " + err.Error())
	}

	return func(ctx *macaron.Context, s session.Store) {
		if ctx.Req.Method == "GET" {
			switch ctx.Req.URL.Path {
			case opt.PathLogin:
				login(ctx, s, opt)
			case opt.PathLogout:
				logout(ctx, s)
			case opt.PathCallback:
				handleOAuth2Callback(ctx, s, opt)
			}
		}
		tk := unmarshallToken(s)
		if tk != nil {
			// check if the access token is expired
			if tk.Expired() && tk.RefreshToken == "" {
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
var LoginRequired macaron.Handler = func() macaron.Handler {
	return func(ctx *macaron.Context, s session.Store) {
		token := unmarshallToken(s)
		if token == nil || token.Expired() {
			next := url.QueryEscape(ctx.Req.URL.RequestURI())
			ctx.Redirect(PathLogin + "?next=" + next)
		}
	}
}()

func login(ctx *macaron.Context, s session.Store, opt *Options) {
	next := extractPath(ctx.Query(KEY_NEXT_PAGE))
	if s.Get(KEY_TOKEN) == nil {
		// User is not logged in.
		if next == "" {
			next = AppSubUrl + "/"
		}
		// println(111, opt.AuthCodeURL(next, "", ""))
		ctx.Redirect(opt.AuthCodeURL(next, "", ""))
		return
	}
	// No need to login, redirect to the next page.
	ctx.Redirect(next)
}

func logout(ctx *macaron.Context, s session.Store) {
	next := extractPath(ctx.Query(KEY_NEXT_PAGE))
	s.Delete(KEY_TOKEN)
	ctx.Redirect(next)
}

func handleOAuth2Callback(ctx *macaron.Context, s session.Store, opt *Options) {
	next := extractPath(ctx.Query("state"))
	code := ctx.Query("code")
	t, err := opt.NewTransportFromCode(code)
	if err != nil {
		// Pass the error message, or allow dev to provide its own
		// error handler.
		println(err.Error())
		ctx.Redirect(PathError)
		return
	}
	// Store the credentials in the session.
	val, _ := json.Marshal(t.Token())
	s.Set(KEY_TOKEN, val)
	ctx.Redirect(next)
}

func unmarshallToken(s session.Store) (t *Token) {
	if s.Get(KEY_TOKEN) == nil {
		return
	}
	data := s.Get(KEY_TOKEN).([]byte)
	var tk Token
	json.Unmarshal(data, &tk)
	return &tk
}

func extractPath(next string) string {
	n, err := url.Parse(next)
	if err != nil {
		return AppSubUrl + "/"
	}
	return n.Path
}
