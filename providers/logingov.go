package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// LoginGovProvider represents an OIDC based Identity Provider
type LoginGovProvider struct {
	*ProviderData

	// TODO (@timothy-spencer): Ideally, the nonce would be in the session state, but the session state
	// is created only upon code redemption, not during the auth, when this must be supplied.
	JWTKey    *rsa.PrivateKey
	PubJWKURL *url.URL
}

var _ Provider = (*LoginGovProvider)(nil)

// For generating a nonce
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		max := big.NewInt(int64(len(letters)))
		bigN, err := rand.Int(rand.Reader, max)
		if err != nil {
			// This should never happen
			panic(err)
		}
		b[i] = letters[bigN.Int64()]
	}
	return string(b)
}

const (
	loginGovProviderName = "login.gov"
	loginGovDefaultScope = "email openid"
)

var (
	// Default Login URL for LoginGov.
	// Pre-parsed URL of https://secure.login.gov/openid_connect/authorize.
	loginGovDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "secure.login.gov",
		Path:   "/openid_connect/authorize",
	}

	// Default Redeem URL for LoginGov.
	// Pre-parsed URL of https://secure.login.gov/api/openid_connect/token.
	loginGovDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "secure.login.gov",
		Path:   "/api/openid_connect/token",
	}

	// Default Profile URL for LoginGov.
	// Pre-parsed URL of https://graph.loginGov.com/v2.5/me.
	loginGovDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "secure.login.gov",
		Path:   "/api/openid_connect/userinfo",
	}
)

// NewLoginGovProvider initiates a new LoginGovProvider
func NewLoginGovProvider(p *ProviderData) *LoginGovProvider {
	p.setProviderDefaults(providerDefaults{
		name:        loginGovProviderName,
		loginURL:    loginGovDefaultLoginURL,
		redeemURL:   loginGovDefaultRedeemURL,
		profileURL:  loginGovDefaultProfileURL,
		validateURL: nil,
		scope:       loginGovDefaultScope,
	})
	return &LoginGovProvider{
		ProviderData: p,
	}
}

func emailFromUserInfo(ctx context.Context, accessToken string, userInfoEndpoint string) (string, error) {
	// parse the user attributes from the data we got and make sure that
	// the email address has been validated.
	var emailData struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}

	// query the user info endpoint for user attributes
	err := requests.New(userInfoEndpoint).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+accessToken).
		Do().
		UnmarshalInto(&emailData)
	if err != nil {
		return "", err
	}

	email := emailData.Email
	if email == "" {
		return "", fmt.Errorf("missing email")
	}

	if !emailData.EmailVerified {
		return "", fmt.Errorf("email %s not listed as verified", email)
	}

	return email, nil
}

func (p *LoginGovProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, http.Header{"Authorization": []string{"Bearer "+s.AccessToken},})
}


// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *LoginGovProvider) Redeem(ctx context.Context, redirect_uri, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}

	claims := &jwt.StandardClaims{
		Issuer:    p.ClientID,
		Subject:   p.ClientID,
		Audience:  p.RedeemURL.String(),
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Id:        randSeq(32),
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	ss, err := token.SignedString(p.JWTKey)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("client_assertion", ss)
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	params.Add("redirect_uri", redirect_uri)

	// Get the token from the body that we got from the token endpoint.
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	// Get the email address
	var email string
	email, err = emailFromUserInfo(ctx, jsonResponse.AccessToken, p.ProfileURL.String())
	if err != nil {
		return nil, err
	}

	session := &sessions.SessionState{
		AccessToken: jsonResponse.AccessToken,
		IDToken:     jsonResponse.IDToken,
		Email:       email,
	}

	session.CreatedAtNow()
	session.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return session, nil
}
