package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/result"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/session"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)

type Credentials struct {
	ClientID     string
	ClientSecret string
}

type Provider struct {
	store    storage.Storage
	sessions *session.Service
	creds    map[string]Credentials // upper-case provider name → creds
}

func New(store storage.Storage, creds map[string]Credentials) *Provider {
	if creds == nil {
		creds = make(map[string]Credentials)
	}
	return &Provider{
		store:    store,
		sessions: session.New(store),
		creds:    creds,
	}
}

func (p *Provider) Name() string { return "oauth" }

func (p *Provider) SetCredentials(provider string, cred Credentials) {
	p.creds[strings.ToUpper(strings.TrimSpace(provider))] = cred
}

type oauthState struct {
	TenantID    string `json:"tenant_id"`
	CallbackURL string `json:"callback_url"`
	Provider    string `json:"provider"`
}

func encodeState(state oauthState) string {
	raw, _ := json.Marshal(state)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeState(encoded string) (oauthState, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return oauthState{}, err
	}
	var state oauthState
	if err := json.Unmarshal(raw, &state); err != nil {
		return oauthState{}, err
	}
	return state, nil
}

func (p *Provider) credentials(provider string) (Credentials, error) {
	c, ok := p.creds[strings.ToUpper(provider)]
	if !ok || c.ClientID == "" || c.ClientSecret == "" {
		return Credentials{}, errors.ErrOAuthProviderNotConfigured
	}
	return c, nil
}

func (p *Provider) LoginURL(_ context.Context, provider, tenantID, callbackURL, backendCallbackURL string) (string, error) {
	provider = strings.ToUpper(provider)
	c, err := p.credentials(provider)
	if err != nil {
		return "", err
	}

	state := encodeState(oauthState{
		TenantID:    tenantID,
		CallbackURL: callbackURL,
		Provider:    provider,
	})

	switch provider {
	case "GOOGLE":
		q := url.Values{}
		q.Set("client_id", c.ClientID)
		q.Set("redirect_uri", backendCallbackURL)
		q.Set("response_type", "code")
		q.Set("scope", "openid email profile")
		q.Set("state", state)
		q.Set("access_type", "online")
		q.Set("prompt", "select_account")
		return "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode(), nil
	case "GITHUB":
		q := url.Values{}
		q.Set("client_id", c.ClientID)
		q.Set("redirect_uri", backendCallbackURL)
		q.Set("scope", "read:user user:email")
		q.Set("state", state)
		return "https://github.com/login/oauth/authorize?" + q.Encode(), nil
	default:
		return "", fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

func (p *Provider) Callback(ctx context.Context, provider, code, state, backendCallbackURL string) (*result.Auth, string, error) {
	parsed, err := decodeState(state)
	if err != nil {
		return nil, "", errors.ErrOAuthStateInvalid
	}

	provider = strings.ToUpper(provider)
	c, err := p.credentials(provider)
	if err != nil {
		return nil, "", err
	}

	profile, err := exchangeCode(provider, c.ClientID, c.ClientSecret, code, backendCallbackURL)
	if err != nil {
		return nil, "", err
	}

	userID, err := p.findOrCreateUser(ctx, profile)
	if err != nil {
		return nil, "", err
	}

	sessionToken, err := p.sessions.Create(ctx, userID)
	if err != nil {
		return nil, "", err
	}

	return &result.Auth{
		SessionToken: sessionToken,
		UserID:       userID,
	}, parsed.CallbackURL, nil
}

type socialProfile struct {
	Provider       string
	ProviderUserID string
	Email          string
	FirstName      string
	LastName       string
}

func (p *Provider) findOrCreateUser(ctx context.Context, profile socialProfile) (string, error) {
	if existing, err := p.store.AuthAccounts().GetByProvider(ctx, profile.Provider, profile.ProviderUserID); err == nil {
		return existing.UserID, nil
	}

	user, err := p.store.Users().GetByEmail(ctx, profile.Email)
	if err == nil {
		_ = p.store.AuthAccounts().Create(ctx, &entities.AuthAccount{
			ID:         uuid.New().String(),
			UserID:     user.ID,
			Provider:   profile.Provider,
			ProviderID: profile.ProviderUserID,
		})
		return user.ID, nil
	}

	var userID string
	err = p.store.Transaction(ctx, func(tx storage.Storage) error {
		userID = uuid.New().String()
		if err := tx.Users().Create(ctx, &entities.User{
			ID:        userID,
			Email:     profile.Email,
			FirstName: profile.FirstName,
			LastName:  profile.LastName,
			Status:    "ACTIVE",
		}); err != nil {
			return err
		}
		return tx.AuthAccounts().Create(ctx, &entities.AuthAccount{
			ID:         uuid.New().String(),
			UserID:     userID,
			Provider:   profile.Provider,
			ProviderID: profile.ProviderUserID,
		})
	})
	return userID, err
}

func exchangeCode(provider, clientID, clientSecret, code, redirectURI string) (socialProfile, error) {
	switch strings.ToUpper(provider) {
	case "GOOGLE":
		return exchangeGoogle(clientID, clientSecret, code, redirectURI)
	case "GITHUB":
		return exchangeGitHub(clientID, clientSecret, code, redirectURI)
	default:
		return socialProfile{}, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func exchangeGoogle(clientID, clientSecret, code, redirectURI string) (socialProfile, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")

	resp, err := http.Post("https://oauth2.googleapis.com/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return socialProfile{}, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return socialProfile{}, err
	}
	if tokenResp.AccessToken == "" {
		return socialProfile{}, errors.ErrOAuthCodeExchangeFailed
	}

	req, _ := http.NewRequest(http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return socialProfile{}, err
	}
	defer userResp.Body.Close()

	var info struct {
		Sub        string `json:"sub"`
		Email      string `json:"email"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&info); err != nil {
		return socialProfile{}, err
	}
	if info.Email == "" {
		return socialProfile{}, errors.ErrOAuthEmailMissing
	}

	return socialProfile{
		Provider:       "GOOGLE",
		ProviderUserID: info.Sub,
		Email:          info.Email,
		FirstName:      info.GivenName,
		LastName:       info.FamilyName,
	}, nil
}

func exchangeGitHub(clientID, clientSecret, code, redirectURI string) (socialProfile, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)

	req, _ := http.NewRequest(http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return socialProfile{}, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return socialProfile{}, err
	}
	if tokenResp.AccessToken == "" {
		return socialProfile{}, errors.ErrOAuthCodeExchangeFailed
	}

	userReq, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/vnd.github+json")
	userResp, err := http.DefaultClient.Do(userReq)
	if err != nil {
		return socialProfile{}, err
	}
	defer userResp.Body.Close()

	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&user); err != nil {
		return socialProfile{}, err
	}

	email := user.Email
	if email == "" {
		emailReq, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user/emails", nil)
		emailReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		emailReq.Header.Set("Accept", "application/vnd.github+json")
		if emailResp, err := http.DefaultClient.Do(emailReq); err == nil {
			defer emailResp.Body.Close()
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if json.NewDecoder(emailResp.Body).Decode(&emails) == nil {
				for _, e := range emails {
					if e.Primary && e.Verified {
						email = e.Email
						break
					}
				}
			}
		}
	}
	if email == "" {
		return socialProfile{}, errors.ErrOAuthEmailMissing
	}

	first, last := splitName(user.Name)
	if first == "" {
		first = user.Login
	}

	return socialProfile{
		Provider:       "GITHUB",
		ProviderUserID: fmt.Sprintf("%d", user.ID),
		Email:          email,
		FirstName:      first,
		LastName:       last,
	}, nil
}

func splitName(full string) (string, string) {
	parts := strings.Fields(strings.TrimSpace(full))
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

func RedirectWithSession(callbackURL, sessionToken string) string {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return callbackURL
	}
	q := u.Query()
	q.Set("session_token", sessionToken)
	u.RawQuery = q.Encode()
	return u.String()
}
