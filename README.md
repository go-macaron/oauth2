oauth2
======

Middleware oauth2 provides support of user login via an OAuth 2.0 backend for [Macaron](https://github.com/Unknwon/macaron).

It currently support Google, GitHub, LinkedIn, Dropbox, Facebook, Weibo and QQ.

## Usage

```go
// ...
m.Use(oauth2.GitHub(oauth2.Options{
	ClientID:     "CLIENT_ID",
	ClientSecret: "CLIENT_SECRET",
	Scopes:       []string{"SCOPE"},
	PathLogin:    "/user/login/oauth2/github",
	PathCallback: "/user/login/github",
	RedirectURL:  "http://localhost:3000/user/login/github",
}))
// ...
```

## Credits

This package is forked from [golang/oauth2](https://github.com/golang/oauth2) and [martini-contrib/oauth2](https://github.com/martini-contrib/oauth2) with modifications.

## License

This project is under Apache v2 License. See the [LICENSE](LICENSE) file for the full license text.
