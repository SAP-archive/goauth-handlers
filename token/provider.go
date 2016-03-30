package token

import (
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type Provider struct {
	oauth2.Config
	Context context.Context
}

func (p *Provider) RequestToken(code string) (*oauth2.Token, error) {
	if p.Context == nil {
		p.Context = context.TODO()
	}
	return p.Exchange(p.Context, code)
}

func (p *Provider) LoginURL(state string) string {
	return p.AuthCodeURL(state)
}
