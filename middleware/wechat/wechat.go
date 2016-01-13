package wechat

import (
	"crypto/sha1"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/mholt/caddy/middleware"
)

type Wechat struct {
	Next         middleware.Handler
	Config       Config
	sessionStore *sessions.FilesystemStore
	jsApiTicket  *ticketInfo
}

type Config struct {
	AppId      string
	Secret     string
	BaseURL    string
	AuthURL    string
	SignInPath string
}

type ticketInfo struct {
	Token     string
	Value     string
	Timestamp int64
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

type wechatTicket struct {
	ErrCode   int    `json:"errcode"`
	ErrMsg    string `json:"errmsg"`
	Value     string `json:"ticket"`
	ExpiresIn int    `json:"expires_in"`
}

const (
	kAccessTokenURL = "https://api.weixin.qq.com/sns/oauth2/access_token"
	kUserInfoURL    = "https://api.weixin.qq.com/sns/userinfo"

	kJSTokenURL  = "https://api.weixin.qq.com/cgi-bin/token"
	kJSTicketURL = "https://api.weixin.qq.com/cgi-bin/ticket/getticket"

	kSessionDir    = ".sessions"
	kSessionKey    = "WECHAT_AUTH_KEY"
	kSessionSecret = "wEchAt_tZj"
)

func (c *Wechat) Init() {
	os.Mkdir(kSessionDir, 0666)
	c.sessionStore = sessions.NewFilesystemStore(kSessionDir, []byte(kSessionSecret))
	c.sessionStore.MaxAge(3600)
	gob.Register(&wechatUserInfo{})

	c.initTicket()
}

func (c Wechat) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !c.shouldAuth(r) {
		if r.URL.Path == "/jsapi_config.js" {
			timestamp := time.Now().Unix()
			nonce := "touzhijia.jz"
			signature := c.getSignature(nonce, timestamp)
			fmt.Fprintf(w, `
			wx.config({
				debug: false,
				appId: '%v',
				timestamp: '%v',
				nonceStr: '%v',
				signature: '%v',
				jsApiList: [
					'onMenuShareTimeline',
					'onMenuShareAppMessage',
					'chooseImage',
					'previewImage',
					'uploadImage',
					'downloadImage'
				]});
			`, c.Config.AppId, timestamp, nonce, signature)
			return 0, nil
		}
		return c.Next.ServeHTTP(w, r)
	}
	// 已经登录
	if user := c.getCurrentUser(r); user != nil {
		middleware.RegisterReplacement("WechatID", user.UnionId)
		return c.Next.ServeHTTP(w, r)
	}
	if r.URL.Path == c.Config.SignInPath {
		_, err := c.login(w, r)
		if err != nil {
			return http.StatusUnauthorized, err
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else if strings.HasPrefix(r.URL.Path, "/api") {
		return http.StatusUnauthorized, errors.New("user not login")
	} else {
		http.Redirect(w, r, c.Config.AuthURL, http.StatusSeeOther)
	}
	return 0, nil
}

func (c *Wechat) shouldAuth(r *http.Request) bool {
	if strings.Contains(r.URL.Path, ".") {
		return false
	}
	return true
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
	session, _ := c.sessionStore.Get(r, kSessionKey)
	session.Values["user"] = user
	session.Save(r, w)
	return
}

func (c Wechat) getCurrentUser(r *http.Request) *wechatUserInfo {
	session, err := c.sessionStore.Get(r, kSessionKey)
	if err != nil {
		return nil
	}
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
	res, err := httpGet(u.String())
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
	res, err := httpGet(u.String())
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

func (c *Wechat) initTicket() {
	c.jsApiTicket = new(ticketInfo)
	ticketBytes, err := ioutil.ReadFile(".ticket")
	if err == nil {
		json.Unmarshal(ticketBytes, c.jsApiTicket)
	}

	go func() {
		for {
			now := time.Now().Unix()
			if now-c.jsApiTicket.Timestamp < 7000 {
				time.Sleep(5 * time.Second)
				continue
			}
			token := c.getJSToken()

			c.jsApiTicket.Token = token
			c.jsApiTicket.Value = c.getJSTicket(token)
			c.jsApiTicket.Timestamp = now
			fmt.Println("generate ticket:", c.jsApiTicket)

			ticketBytes, err := json.Marshal(c.jsApiTicket)
			if err == nil {
				ioutil.WriteFile(".ticket", ticketBytes, 0666)
			}
		}
	}()
}

func (c *Wechat) getJSTicket(token string) string {
	u, _ := url.Parse(kJSTicketURL)
	q := u.Query()
	q.Set("access_token", token)
	q.Set("type", "jsapi")
	u.RawQuery = q.Encode()
	resp, err := httpGet(u.String())
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)
	ticket := &wechatTicket{}
	err = d.Decode(ticket)
	if err != nil {
		panic(err)
	}
	if ticket.ErrCode != 0 {
		panic(ticket.ErrMsg)
	}
	return ticket.Value
}

func (c *Wechat) getJSToken() string {
	u, _ := url.Parse(kJSTokenURL)
	q := u.Query()
	q.Set("grant_type", "client_credential")
	q.Set("appid", c.Config.AppId)
	q.Set("secret", c.Config.Secret)
	u.RawQuery = q.Encode()
	resp, err := httpGet(u.String())
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)
	access := &wechatAccess{}
	err = d.Decode(access)
	if err != nil {
		panic(err)
	}
	return access.Token
}

func (c *Wechat) getSignature(nonce string, timestamp int64) string {
	text := fmt.Sprintf("jsapi_ticket=%v&noncestr=%v&timestamp=%v&url=%v",
		c.jsApiTicket.Value, nonce, timestamp, c.Config.BaseURL)
	return fmt.Sprintf("%x", sha1.Sum([]byte(text)))
}

func httpGet(url string) (*http.Response, error) {
	cli := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Close = true
	return cli.Do(req)
}
