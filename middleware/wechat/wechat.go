package wechat

import (
	"crypto/sha1"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math/rand"
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
	JSAPIDebug bool
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

	kJSTicketURL = "http://10.173.166.144:3006/api/meta"

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

const indexTemplate = `
<!doctype html>
<html lang="zh">
  <head>
    <meta charset="utf-8">
    <title>网贷记账</title>
    <meta name="viewport" content="width=device-width,initial-scale=1.0,user-scalable=no" />
    <meta name="format-detection" content="telephone=no" />
  </head>
  <body>
    <div id="root"></div>
    <script src="/bundle.js"></script>
    <script src="http://res.wx.qq.com/open/js/jweixin-1.0.0.js"></script>
    <script>
      wx.config({
        debug: {{.Debug}},
        appId: '{{.AppId}}',
        timestamp: '{{.Timestamp}}',
        nonceStr: '{{.Nonce}}',
        signature: '{{.Signature}}',
        jsApiList: [
          'onMenuShareTimeline',
          'onMenuShareAppMessage',
          'previewImage',
        ]
      });
      {{if .Debug}}
      wx.error(function(res){
        alert(res);
      });
      {{end}}
      wx.ready(function(){
        wx.onMenuShareTimeline({
          title: '网贷记账--公测上线',
          link: '{{.BaseURL}}',
          imgUrl: 'http://static.touzhijia.com/m/billing/share.png'
        });
        wx.onMenuShareAppMessage({
          title: '网贷记账--公测上线',
          desc: '轻松打理网贷资产、随时掌控投资和回款信息',
          link: '{{.BaseURL}}',
          imgUrl: 'http://static.touzhijia.com/m/billing/share.png'
        });
      });
    </script>

  </body>
</html>
`

func (c Wechat) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if !c.shouldAuth(r) {
		return c.Next.ServeHTTP(w, r)
	}
	// 已经登录
	if user := c.getCurrentUser(r); user != nil {
		if r.URL.Path == "/" {
			timestamp := time.Now().Unix()
			nonce := getNonceStr(8)
			signature := c.getSignature(c.Config.BaseURL+r.URL.String(), nonce, timestamp)
			t, err := template.New("index").Parse(indexTemplate)
			if err != nil {
				return http.StatusInternalServerError, err
			}
			err = t.Execute(w, map[string]interface{}{
				"BaseURL":   c.Config.BaseURL,
				"Debug":     c.Config.JSAPIDebug,
				"AppId":     c.Config.AppId,
				"Timestamp": timestamp,
				"Nonce":     nonce,
				"Signature": signature,
			})
			if err != nil {
				return http.StatusInternalServerError, err
			}
			return http.StatusOK, nil
		}
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

func getJsTicket() (ticket string) {
	cli := &http.Client{}
	resp, err := cli.Get(kJSTicketURL)
	if err != nil {
		return
	}
	d := json.NewDecoder(resp.Body)
	m := map[string]string{}
	if err := d.Decode(&m); err != nil {
		return
	}
	var ok bool
	if ticket, ok = m["jsapi_ticket"]; !ok {
		return ""
	}
	return
}

func (c *Wechat) getSignature(url, nonce string, timestamp int64) string {
	ticket := getJsTicket()
	text := fmt.Sprintf("jsapi_ticket=%v&noncestr=%v&timestamp=%v&url=%v",
		ticket, nonce, timestamp, url)
	sig := fmt.Sprintf("%x", sha1.Sum([]byte(text)))
	return sig
}

var (
	kLETTERS = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func getNonceStr(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = kLETTERS[rand.Intn(len(kLETTERS))]
	}
	return string(b)
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
