package huizhi

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/markbates/goth"
)

// Session stores data during the auth process
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// GetAuthURL returns the URL for the authentication end-point
func (s *Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not been set")
	}
	return s.AuthURL, nil
}

// Authorize the session with the passed auth code
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry

	return token.AccessToken, err
}

// Marshal the session into a string
func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// String is equivalent to Marshal
func (s *Session) String() string {
	return s.Marshal()
}

// UnmarshalSession wil unmarshal a JSON string into a session
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.Unmarshal([]byte(data), s)
	return s, err
}

// UnmarshalString unmarshals a JSON string into a session
func (s *Session) UnmarshalString(data string) error {
	j := struct {
		AuthURL      string `json:"AuthURL"`
		AccessToken  string `json:"AccessToken"`
		RefreshToken string `json:"RefreshToken"`
	}{}
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return err
	}
	s.AuthURL = j.AuthURL
	s.AccessToken = j.AccessToken
	s.RefreshToken = j.RefreshToken
	return nil
}
