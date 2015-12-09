package wechat

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/sessions"
	"github.com/mholt/caddy/middleware"
)

type Wechat struct {
	Next   middleware.Handler
	Config Config

	sessionStore *sessions.FilesystemStore
}

type Config struct {
	AppId      string
	Secret     string
	AuthURL    string
	SignInPath string
}

type wechatError struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type wechatAccess struct {
	Token        string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenId       string `json:"openid"`
	UnionId      string `json:"unionid"`
	Scope        string `json:"scope"`
	wechatError
}

type wechatUserInfo struct {
	Nickname     string `json:"nickname"`
	Sex          int    `json:"sex"`
	Province     string `json:"province"`
	City         string `json:"city"`
	Country      string `json:"country"`
	HeadImageUrl string `json:"headimgurl"`
	UnionId      string `json:"unionid"`
	wechatError
}

const (
	kAccessTokenURL = "https://api.weixin.qq.com/sns/oauth2/access_token"
	kUserInfoURL    = "https://api.weixin.qq.com/sns/userinfo"

	kSessionDir    = ".sessions"
	kSessionKey    = "WECHAT_AUTH_KEY"
	kSessionSecret = "wEchAt_tZj"
)

func (c *Wechat) Init() {
	os.Mkdir(kSessionDir, 0666)
	c.sessionStore = sessions.NewFilesystemStore(kSessionDir, []byte(kSessionSecret))
	c.sessionStore.MaxAge(3600)
	gob.Register(&wechatUserInfo{})
}

func (c Wechat) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// 已经登录
	if user := c.getCurrentUser(r); user != nil {
		fmt.Println(user)
		middleware.RegisterReplacement("WechatID", user.UnionId)
		return c.Next.ServeHTTP(w, r)
	}
	if r.URL.Path == c.Config.SignInPath {
		_, err := c.login(w, r)
		if err != nil {
			return http.StatusUnauthorized, err
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, c.Config.AuthURL, http.StatusSeeOther)
	}
	return 0, nil
}

func (c *Wechat) login(w http.ResponseWriter, r *http.Request) (user *wechatUserInfo, err error) {
	q := r.URL.Query()
	code := q.Get("code")
	var access *wechatAccess
	if access, err = c.getAccess(code); err != nil {
		return
	}
	if user, err = c.getUserInfo(access); err != nil {
		return
	}
	session, err := c.sessionStore.Get(r, kSessionKey)
	if err != nil {
		return
	}
	session.Values["user"] = user
	session.Save(r, w)
	return
}

func (c Wechat) getCurrentUser(r *http.Request) *wechatUserInfo {
	session, err := c.sessionStore.Get(r, kSessionKey)
	if err != nil {
		return nil
	}
	fmt.Println(session.Values)
	if user, ok := session.Values["user"].(*wechatUserInfo); ok {
		return user
	}
	return nil
}

func (w Wechat) getAccess(code string) (a *wechatAccess, err error) {
	u, _ := url.Parse(kAccessTokenURL)
	q := u.Query()
	q.Set("appid", w.Config.AppId)
	q.Set("secret", w.Config.Secret)
	q.Set("code", code)
	q.Set("grant_type", "authorization_code")
	u.RawQuery = q.Encode()
	res, err := http.Get(u.String())
	if err != nil {
		return
	}
	defer res.Body.Close()
	d := json.NewDecoder(res.Body)
	a = &wechatAccess{}
	err = d.Decode(a)
	if err != nil {
		return
	}
	if a.ErrCode > 0 {
		err = errors.New(a.ErrMsg)
		return
	}
	return
}

func (w Wechat) getUserInfo(a *wechatAccess) (user *wechatUserInfo, err error) {
	u, _ := url.Parse(kUserInfoURL)
	q := u.Query()
	q.Set("access_token", a.Token)
	q.Set("openid", a.OpenId)
	q.Set("lang", "zh_CN")
	u.RawQuery = q.Encode()
	res, err := http.Get(u.String())
	if err != nil {
		return
	}
	defer res.Body.Close()
	d := json.NewDecoder(res.Body)
	user = &wechatUserInfo{}
	err = d.Decode(user)
	if err != nil {
		return
	}
	if user.ErrCode > 0 {
		err = errors.New(user.ErrMsg)
		return
	}
	return
}
