package auth

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	oauthResponseType        = "code"
	oauthCodeChallengeMethod = "S256"
	oauthScope               = "openid profile email offline_access"
	codeChallengeLen         = 32
	serverPort               = "3000"
)

//Singer is the interface that wraps the Sing method
type Singer interface {
	Sign(req *http.Request) *http.Request
}

//Auth0 represents the structure with auth0 authorization config.
type Auth0 struct {
	// Domain is the Auth0 domain without the protocol.
	Domain   string
	ClientID string

	state        string
	codeVerifier string
}

// GetToken function return Auth0 authorization token
// It opens new page with Auth0 universal login that redirects to localhost:3000
func (c *Auth0) GetToken() (*OAuthToken, error) {
	token := loadTokenFromFile(c.hash())
	if token != nil {
		log.Debug("Found valid token in the .token file")
		return token, nil
	}

	responseChan, errorChan := make(chan OAuthToken), make(chan error)
	server := http.Server{Addr: fmt.Sprintf("localhost:%s", serverPort)}
	defer server.Close()
	go c.serveAuthPage(responseChan, errorChan, &server)

	loginURL, err := c.getAuth0LoginURL()
	if err != nil {
		return nil, fmt.Errorf("cannot generate login url for authentication: %s", err.Error())
	}

	log.Info(loginURL)

	err = openBrowser(loginURL)
	if err != nil {
		return nil, fmt.Errorf("cannot open the Internet browser for authentication: %s", err.Error())
	}

	select {
	case err := <-errorChan:
		return nil, err
	case token := <-responseChan:
		token.ClientID = c.ClientID
		token.Domain = c.Domain
		token.save(c.hash())
		return &token, nil
	}
}

func (c *Auth0) hash() string {
	hash := md5.Sum([]byte(c.ClientID + c.Domain))
	return fmt.Sprintf("%x", hash)
}

func (c *Auth0) getRandomString(l int) (string, error) {
	b := make([]byte, l)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

func (c *Auth0) getCodeChallenge() (string, error) {
	randStr, err := c.getRandomString(codeChallengeLen)
	if err != nil {
		return "", err
	}
	c.codeVerifier = randStr

	hash := sha256.New()
	if _, err := hash.Write([]byte(randStr)); err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash.Sum(nil)), nil
}

func (c *Auth0) getAuth0LoginURL() (string, error) {
	challenge, err := c.getCodeChallenge()
	if err != nil {
		return "", err
	}
	state, err := c.getRandomString(codeChallengeLen)
	if err != nil {
		return "", err
	}
	c.state = state

	return fmt.Sprintf("https://%s/authorize?response_type=code&client_id=%s&code_challenge=%s&code_challenge_method=S256&redirect_uri=%s&scope=%s&state=%s",
		c.Domain, c.ClientID, challenge, fmt.Sprintf("http://localhost:%s", serverPort), oauthScope, state), nil
}

// TokenRequest is an input used to request new token
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	CodeVerifier string `json:"code_verifier"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
}

func (c *Auth0) handleLoginRedirect(r *http.Request) (*OAuthToken, error) {
	query := r.URL.Query()
	receivedState, ok := query["state"]
	if !ok || len(receivedState) == 0 || receivedState[0] != c.state {
		return nil, errors.New("Received invalid oauth state")
	}

	code, ok := query["code"]
	if !ok || len(code) == 0 {
		return nil, errors.New("Missing code in request")
	}

	data, err := json.Marshal(TokenRequest{
		ClientID:     c.ClientID,
		GrantType:    "authorization_code",
		CodeVerifier: c.codeVerifier,
		Code:         code[0],
		RedirectURI:  fmt.Sprintf("http://localhost:%s", serverPort),
	})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s/oauth/token", c.Domain)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	token := OAuthToken{}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (c *Auth0) serveAuthPage(responseToken chan OAuthToken, errorChan chan error, server *http.Server) {
	log.Debug(fmt.Sprintf("Serve web page localhost:%s", serverPort))

	t, err := getPageTemplate()
	if err != nil {
		log.Error("Failed to load auth page", err.Error())
		errorChan <- err
		return
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		token, err := c.handleLoginRedirect(r)
		if err != nil {
			errorChan <- err
			return
		}

		responseToken <- *token
		t.Execute(w, *c)
	}

	http.HandleFunc("/", handler)
	server.ListenAndServe()
}
