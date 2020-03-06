package oauth2

import (
	"net/url"
)

type ProviderData struct {
	ClientID          string
	ClientSecret      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	Scope             string
	ApprovalPrompt    string
}

func (p *ProviderData) Data() *ProviderData { return p }
