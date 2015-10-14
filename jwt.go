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

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-macaron/oauth2/jws"
)

var (
	defaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	defaultHeader    = &jws.Header{Algorithm: "RS256", Typ: "JWT"}
)

// ParseKey converts the binary contents of a private key file
// to an *rsa.PrivateKey. It detects whether the private key is in a
// PEM container or not. If so, it extracts the the private key
// from PEM container before conversion. It only supports PEM
// containers with no passphrase.
func ParseKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("oauth2: private key is invalid")
	}
	return parsed, nil
}

func makeTwoLeggedFetcher(o *Options) func(t *Token) (*Token, error) {
	return func(t *Token) (*Token, error) {
		if t == nil {
			t = &Token{}
		}
		claimSet := &jws.ClaimSet{
			Iss:   o.Email,
			Scope: strings.Join(o.Scopes, " "),
			Aud:   o.AUD.String(),
		}
		if o.Subject != "" {
			claimSet.Sub = o.Subject
			// prn is the old name of sub. Keep setting it
			// to be compatible with legacy OAuth 2.0 providers.
			claimSet.Prn = o.Subject
		}
		payload, err := jws.Encode(defaultHeader, claimSet, o.PrivateKey)
		if err != nil {
			return nil, err
		}
		v := url.Values{}
		v.Set("grant_type", defaultGrantType)
		v.Set("assertion", payload)
		c := o.Client
		if c == nil {
			c = &http.Client{}
		}
		resp, err := c.PostForm(o.AUD.String(), v)
		if err != nil {
			return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
		}
		if c := resp.StatusCode; c < 200 || c > 299 {
			return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", resp.Status, body)
		}
		b := make(map[string]interface{})
		if err := json.Unmarshal(body, &b); err != nil {
			return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
		}
		token := &Token{}
		token.AccessToken, _ = b["access_token"].(string)
		token.TokenType, _ = b["token_type"].(string)
		token.Raw = b
		if e, ok := b["expires_in"].(int); ok {
			token.Expiry = time.Now().Add(time.Duration(e) * time.Second)
		}
		if idtoken, ok := b["id_token"].(string); ok {
			// decode returned id token to get expiry
			claimSet, err := jws.Decode(idtoken)
			if err != nil {
				return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
			}
			token.Expiry = time.Unix(claimSet.Exp, 0)
			return token, nil
		}
		return token, nil
	}
}
