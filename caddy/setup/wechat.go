package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/wechat"
)

// Wechat configures a new Wechat middleware instance.
func Wechat(c *Controller) (middleware.Middleware, error) {
	config, err := wechatParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		w := wechat.Wechat{Next: next, Config: config}
		w.Init()
		return w
	}, nil
}

func wechatParse(c *Controller) (wechat.Config, error) {
	config := wechat.Config{
		SignInPath: "/signin",
	}
	for c.Next() {
		// No extra args expected
		if len(c.RemainingArgs()) > 0 {
			return config, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "appid":
				if !c.NextArg() {
					return config, c.ArgErr()
				}
				config.AppId = c.Val()
			case "secret":
				if !c.NextArg() {
					return config, c.ArgErr()
				}
				config.Secret = c.Val()
			case "auth_url":
				if !c.NextArg() {
					return config, c.ArgErr()
				}
				config.AuthURL = c.Val()
			case "signin_path":
				if !c.NextArg() {
					return config, c.ArgErr()
				}
				config.SignInPath = c.Val()
			}
		}
	}
	return config, nil
}
