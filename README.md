# OAuth2


Middleware oauth2 provides support of user login via an OAuth 2.0 backend for [Macaron](https://github.com/go-macaron/macaron).

## Usage

```go
// ...
m.Use(oauth2.Google(
	&goauth2.Config{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		Scopes:       []string{"https://www.googleapis.com/auth/drive"},
		RedirectURL:  "redirect_url",
	},
))
// ...
```

## Credits

This package is forked from [martini-contrib/oauth2](https://github.com/martini-contrib/oauth2) with modifications.

## License

This project is under Apache v2 License. See the [LICENSE](LICENSE) file for the full license text.
