package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// OAuthToken contains access_token, id_token and refresh token returned by the oauth service
type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`

	// Additional data stored locally with the token
	ExpiresInDate *time.Time `json:"expires_in_date"`
	Domain        string     `json:"domain"`
	ClientID      string     `json:"client_id"`
	Hash          string     `json:"hash"`
}

// Sign methods adds authorization header to the request
// It uses ID token to sign request
func (c *OAuthToken) Sign(req *http.Request) *http.Request {
	req.Header["Authorization"] = []string{c.IDToken}
	return req
}

// Invalidate function removes cached access token together with the refresh token
func (c *OAuthToken) Invalidate() {
	os.Remove(getTokenPath(c.Hash))
}

// Expired Returns true if token is expired
func (c *OAuthToken) Expired() bool {
	if c.ExpiresInDate != nil && c.ExpiresInDate.After(time.Now().Add(time.Minute*5)) {
		return false
	}
	return true
}

func (c *OAuthToken) save(configHash string) error {
	c.Hash = configHash
	t := time.Now().Add(time.Second * time.Duration(c.ExpiresIn))
	c.ExpiresInDate = &t

	os.MkdirAll(filepath.Dir(getTokenPath(configHash)), os.ModePerm)
	file, err := os.OpenFile(getTokenPath(configHash), os.O_WRONLY|os.O_CREATE, 0660)
	if err != nil {
		return fmt.Errorf("open oauth token file %w", err)
	}
	defer file.Close()

	data, _ := json.Marshal(c)
	err = file.Truncate(0)
	if err != nil {
		return fmt.Errorf("clear oauth token file %w", err)
	}
	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("write oauth token file %w", err)
	}
	return nil
}

// RefreshTokenRequest is an input used to request new access code using refresh token
type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
}

// RefreshTokenResponse contains access token
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *OAuthToken) refresh() error {
	url := fmt.Sprintf("https://%s/oauth/token", c.Domain)
	data, err := json.Marshal(RefreshTokenRequest{
		ClientID:     c.ClientID,
		RefreshToken: c.RefreshToken,
		GrantType:    "refresh_token",
	})
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	newToken := RefreshTokenResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&newToken); err != nil {
		return err
	}

	c.AccessToken = newToken.AccessToken
	c.IDToken = newToken.IDToken
	c.ExpiresIn = newToken.ExpiresIn
	c.save(c.Hash)

	return nil
}

// loadTokenFromFile loads token from file, returns nil if token does not exist or is invalid
func loadTokenFromFile(configHash string) *OAuthToken {
	fileName := getTokenPath(configHash)

	file, err := os.OpenFile(fileName, os.O_RDONLY, 0660)
	if err != nil {
		log.WithError(err).Debug("open file")
		return nil
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		log.WithError(err).Debug("read file")
		os.Remove(fileName)
		return nil
	}

	token := &OAuthToken{}
	err = json.Unmarshal(b, token)
	if err != nil {
		log.WithError(err).Debug("parse file")
		os.Remove(fileName)
		return nil
	}

	if token.Expired() {
		err = token.refresh()
		if err != nil {
			log.WithError(err).Debug("refresh token")
			os.Remove(fileName)
			return nil
		}
	}

	return token
}

func getTokenPath(hash string) string {
	fileName := fmt.Sprintf(".token-%s", hash)
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return fileName
	}

	return filepath.Join(cacheDir, "nc-oauth-cli", fileName)
}
