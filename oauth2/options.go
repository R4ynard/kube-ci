package oauth2

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/18F/hmacauth"
)

// Configuration Options that can be set by Command Line Flag, or Config File
type Options struct {
	ProxyPrefix  string `flag:"proxy-prefix" cfg:"proxy-prefix"`
	RedirectURL  string `flag:"redirect-url" cfg:"redirect_url"`
	ClientID     string `flag:"client-id" cfg:"client_id" env:"OAUTH2_PROXY_CLIENT_ID"`
	ClientSecret string `flag:"client-secret" cfg:"client_secret" env:"OAUTH2_PROXY_CLIENT_SECRET"`

	GitHubOrg  string `flag:"github-org" cfg:"github_org"`
	GitHubTeam string `flag:"github-team" cfg:"github_team"`

	CookieName     string        `flag:"cookie-name" cfg:"cookie_name" env:"OAUTH2_PROXY_COOKIE_NAME"`
	CookieSecret   string        `flag:"cookie-secret" cfg:"cookie_secret" env:"OAUTH2_PROXY_COOKIE_SECRET"`
	CookieDomain   string        `flag:"cookie-domain" cfg:"cookie_domain" env:"OAUTH2_PROXY_COOKIE_DOMAIN"`
	CookieExpire   time.Duration `flag:"cookie-expire" cfg:"cookie_expire" env:"OAUTH2_PROXY_COOKIE_EXPIRE"`
	CookieRefresh  time.Duration `flag:"cookie-refresh" cfg:"cookie_refresh" env:"OAUTH2_PROXY_COOKIE_REFRESH"`
	CookieSecure   bool          `flag:"cookie-secure" cfg:"cookie_secure"`
	CookieHttpOnly bool          `flag:"cookie-httponly" cfg:"cookie_httponly"`

	Upstream string `flag:"upstream" cfg:"upstream"`

	LoginURL          string `flag:"login-url" cfg:"login_url"`
	RedeemURL         string `flag:"redeem-url" cfg:"redeem_url"`
	ProtectedResource string `flag:"resource" cfg:"resource"`
	ValidateURL       string `flag:"validate-url" cfg:"validate_url"`
	Scope             string `flag:"scope" cfg:"scope"`
	ApprovalPrompt    string `flag:"approval-prompt" cfg:"approval_prompt"`

	SignatureKey string `flag:"signature-key" cfg:"signature_key" env:"OAUTH2_PROXY_SIGNATURE_KEY"`

	// internal values that are set after config validation
	redirectURL   *url.URL
	proxyURL      *url.URL
	provider      *gitHubProvider
	signatureData *SignatureData
}

type SignatureData struct {
	hash crypto.Hash
	key  string
}

func NewOptions() *Options {
	return &Options{
		ProxyPrefix:    "/oauth2",
		CookieName:     "_kubeci_oauth2_proxy",
		CookieSecure:   true,
		CookieHttpOnly: true,
		CookieExpire:   time.Duration(168) * time.Hour,
		CookieRefresh:  time.Duration(0),
		ApprovalPrompt: "force",
	}
}

func parseURL(to_parse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(to_parse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, to_parse, err))
	}
	return parsed, msgs
}

func (o *Options) Validate() error {
	msgs := make([]string, 0)
	if o.Upstream == "" {
		msgs = append(msgs, "missing setting: upstream")
	}
	if o.CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}
	if o.ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	if o.ClientSecret == "" {
		msgs = append(msgs, "missing setting: client-secret")
	}

	o.redirectURL, msgs = parseURL(o.RedirectURL, "redirect", msgs)

	upstreamURL, err := url.Parse(o.Upstream)
	if err != nil {
		msgs = append(msgs, fmt.Sprintf(
			"error parsing upstream=%q %s",
			upstreamURL, err))
	}
	o.proxyURL = upstreamURL

	msgs = parseProviderInfo(o, msgs)

	if o.CookieRefresh != time.Duration(0) {
		valid_cookie_secret_size := false
		for _, i := range []int{16, 24, 32} {
			if len(secretBytes(o.CookieSecret)) == i {
				valid_cookie_secret_size = true
			}
		}
		var decoded bool
		if string(secretBytes(o.CookieSecret)) != o.CookieSecret {
			decoded = true
		}
		if valid_cookie_secret_size == false {
			var suffix string
			if decoded {
				suffix = fmt.Sprintf(" note: cookie secret was base64 decoded from %q", o.CookieSecret)
			}
			msgs = append(msgs, fmt.Sprintf(
				"cookie_secret must be 16, 24, or 32 bytes "+
					"to create an AES cipher when "+
					"pass_access_token == true or "+
					"cookie_refresh != 0, but is %d bytes.%s",
				len(secretBytes(o.CookieSecret)), suffix))
		}
	}

	if o.CookieRefresh >= o.CookieExpire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%s) must be less than "+
				"cookie_expire (%s)",
			o.CookieRefresh.String(),
			o.CookieExpire.String()))
	}

	msgs = parseSignatureKey(o, msgs)
	msgs = validateCookieName(o, msgs)

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseProviderInfo(o *Options, msgs []string) []string {
	p := &ProviderData{
		Scope:          o.Scope,
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		ApprovalPrompt: o.ApprovalPrompt,
	}
	p.LoginURL, msgs = parseURL(o.LoginURL, "login", msgs)
	p.RedeemURL, msgs = parseURL(o.RedeemURL, "redeem", msgs)
	p.ValidateURL, msgs = parseURL(o.ValidateURL, "validate", msgs)
	p.ProtectedResource, msgs = parseURL(o.ProtectedResource, "resource", msgs)
	ghProvider := newGitHubProvider(p)
	ghProvider.setOrgTeam(o.GitHubOrg, o.GitHubTeam)
	o.provider = ghProvider

	return msgs
}

func parseSignatureKey(o *Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	if hash, err := hmacauth.DigestNameToCryptoHash(algorithm); err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+
			o.SignatureKey)
	} else {
		o.signatureData = &SignatureData{hash, secretKey}
	}
	return msgs
}

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// secretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func secretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}
