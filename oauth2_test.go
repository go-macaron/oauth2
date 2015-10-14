// Copyright 2014 Google Inc. All Rights Reserved.
// Copyright 2014 The Macaron Authors
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

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type mockTransport struct {
	rt func(req *http.Request) (resp *http.Response, err error)
}

func (t *mockTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	return t.rt(req)
}

type mockCache struct {
	token   *Token
	readErr error
}

func (c *mockCache) ReadToken() (*Token, error) {
	return c.token, c.readErr
}

func (c *mockCache) WriteToken(*Token) {
	// do nothing
}

func newOpts(path string) *Options {
	au, err := url.Parse(path + "/auth")
	if err != nil {
		println(err.Error())
		return nil
	}
	tu, err := url.Parse(path + "/token")
	if err != nil {
		println(err.Error())
		return nil
	}

	opts, _ := New(&Options{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes:       []string{"scope1", "scope2"},
		AuthURL:      au,
		TokenURL:     tu,
	})
	return opts
}

func TestAuthCodeURL(t *testing.T) {
	opts := newOpts("server")
	url := opts.AuthCodeURL("foo", "offline", "force")
	if url != "server/auth?access_type=offline&approval_prompt=force&client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=foo" {
		t.Errorf("Auth code URL doesn't match the expected, found: %v", url)
	}
}

func TestAuthCodeURL_Optional(t *testing.T) {
	au, err := url.Parse("auth-url")
	tu, err := url.Parse("token-token")
	opts, _ := New(&Options{
		ClientID: "CLIENT_ID",
		AuthURL:  au,
		TokenURL: tu,
	})
	url := opts.AuthCodeURL("", "", "")
	if url != "auth-url?client_id=CLIENT_ID&response_type=code" {
		t.Fatalf("Auth code URL doesn't match the expected, found: %v", url)
	}
	_ = err
}

func TestExchangeRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "client_id=CLIENT_ID&code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL&scope=scope1+scope2" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))
	defer ts.Close()
	opts := newOpts(ts.URL)
	tr, err := opts.NewTransportFromCode("exchange-code")
	if err != nil {
		t.Error(err)
	}
	tok := tr.Token()
	if tok.Expired() {
		t.Errorf("Token shouldn't be expired.")
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}
	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}
}

func TestExchangeRequest_JSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected exchange request URL, %v is found.", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if headerAuth != "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ=" {
			t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "client_id=CLIENT_ID&code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL&scope=scope1+scope2" {
			t.Errorf("Unexpected exchange payload, %v is found.", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "90d64460d14870c08c81352a05dedd3465940a7c", "scope": "user", "token_type": "bearer", "expires_in": 86400}`))
	}))
	defer ts.Close()
	opts := newOpts(ts.URL)
	tr, err := opts.NewTransportFromCode("exchange-code")
	if err != nil {
		t.Error(err)
	}
	tok := tr.Token()
	if tok.Expiry.IsZero() {
		t.Errorf("Token expiry should not be zero.")
	}
	if tok.Expired() {
		t.Errorf("Token shouldn't be expired.")
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}
	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}
}

func TestExchangeRequest_BadResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()
	opts := newOpts(ts.URL)
	tr, err := opts.NewTransportFromCode("exchange-code")
	if err != nil {
		t.Error(err)
	}
	tok := tr.Token()
	if tok.AccessToken != "" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
}

func TestExchangeRequest_BadResponseType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":123,  "scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()
	opts := newOpts(ts.URL)
	tr, err := opts.NewTransportFromCode("exchange-code")
	if err != nil {
		t.Error(err)
	}
	tok := tr.Token()
	if tok.AccessToken != "" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
}

func TestExchangeRequest_NonBasicAuth(t *testing.T) {
	tr := &mockTransport{
		rt: func(r *http.Request) (w *http.Response, err error) {
			headerAuth := r.Header.Get("Authorization")
			if headerAuth != "" {
				t.Errorf("Unexpected authorization header, %v is found.", headerAuth)
			}
			return nil, errors.New("no response")
		},
	}
	c := &http.Client{Transport: tr}

	au, err := url.Parse("https://accounts.google.com/auth")
	tu, err := url.Parse("https://accounts.google.com/token")
	opts, _ := New(&Options{
		ClientID: "CLIENT_ID",
		AuthURL:  au,
		TokenURL: tu,
		Client:   c,
	})
	if err != nil {
		t.Error(err)
	}
	opts.NewTransportFromCode("code")
}

func TestTokenRefreshRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/somethingelse" {
			return
		}
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected token refresh request URL, %v is found.", r.URL)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) != "client_id=CLIENT_ID&grant_type=refresh_token&refresh_token=REFRESH_TOKEN" {
			t.Errorf("Unexpected refresh token payload, %v is found.", string(body))
		}
	}))
	defer ts.Close()
	opts := newOpts(ts.URL)
	tr := opts.NewTransport()
	tr.token = &Token{RefreshToken: "REFRESH_TOKEN"}
	c := http.Client{Transport: tr}
	c.Get(ts.URL + "/somethingelse")
}

func TestFetchWithNoRefreshToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/somethingelse" {
			return
		}
		if r.URL.String() != "/token" {
			t.Errorf("Unexpected token refresh request URL, %v is found.", r.URL)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) != "client_id=CLIENT_ID&grant_type=refresh_token&refresh_token=REFRESH_TOKEN" {
			t.Errorf("Unexpected refresh token payload, %v is found.", string(body))
		}
	}))
	defer ts.Close()
	opts := newOpts(ts.URL)
	tr := opts.NewTransport()
	c := http.Client{Transport: tr}
	_, err := c.Get(ts.URL + "/somethingelse")
	if err == nil {
		t.Errorf("Fetch should return an error if no refresh token is set")
	}
}

func TestCacheNoToken(t *testing.T) {
	au, err := url.Parse("/auth")
	tu, err := url.Parse("/token")
	opts, _ := New(&Options{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		AuthURL:      au,
		TokenURL:     tu,
	})
	if err != nil {
		t.Error(err)
	}
	tr, err := opts.NewTransportFromTokenStore(&mockCache{token: nil, readErr: nil})
	if err != nil {
		t.Errorf("No error expected, %v is found", err)
	}
	if tr != nil {
		t.Errorf("No transport should have been initiated, tr is found to be %v", tr)
	}
}
