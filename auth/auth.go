package auth

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/websocket"
)

const (
	UserPoolEnv = "USER_POOL_ID"
	ClientEnv   = "CLIENT_ID"
	HostedUiEnv = "HOSTED_UI"

	serverPort = "3000"
)

//Singer is the interface that wraps the Sing method
type Singer interface {
	Sign(req *http.Request) *http.Request
}

//CognitoAuth represents the structure with cognito authorization config.
type CognitoAuth struct {
	UserPoolID     string
	ClientID       string
	HostedUIDomain string
	ServerPort     string
	Region         string
}

//CognitoToken is the type that represents the token returned by the Cognito authorizer.
//CognitoToken implements Singer interface
type CognitoToken struct {
	Token          string    `json:"token"`
	ExpirationDate time.Time `json:"expiration_date"`

	auth *CognitoAuth
}

//Sign methods adds authorization header to the request
func (c *CognitoToken) Sign(req *http.Request) *http.Request {
	req.Header["Authorization"] = []string{c.Token}
	return req
}

//Invalidate function removes .token file
func (c *CognitoToken) Invalidate() {
	if c.auth != nil {
		os.Remove(c.auth.getTokenPath())
	}
}

//NewCongitoAuthorizer Returns new congito authorizer
func NewCongitoAuthorizer(UserPoolID, ClientID, HostedUIDomain string) *CognitoAuth {
	config := &CognitoAuth{
		UserPoolID:     UserPoolID,
		ClientID:       ClientID,
		HostedUIDomain: HostedUIDomain,
		ServerPort:     serverPort,
	}
	config.Region = strings.Split(config.UserPoolID, "_")[0]
	return config
}

//GetAuthorizerFromEnv creates new cognito authorizer using environment variables
//If values passed as parameters are not empty they pverride env variables
//If any of the required parameters is missing GetAuthorizerFromEnv return an error
func GetAuthorizerFromEnv(UserPoolID, ClientID, HostedUIDomain string) (*CognitoAuth, error) {
	overrideEnv := func(env, value string) string {
		if len(value) > 0 {
			return value
		}
		return os.Getenv(env)
	}
	config := NewCongitoAuthorizer(
		overrideEnv(UserPoolEnv, UserPoolID),
		overrideEnv(ClientEnv, ClientID),
		overrideEnv(HostedUiEnv, HostedUIDomain),
	)
	if len(config.ClientID) == 0 || len(config.HostedUIDomain) == 0 || len(config.UserPoolID) == 0 {
		return nil, errors.New("Missing cognito settings. Please set the USER_POOL_ID, CLIENT_ID and HOSTED_UI variables")
	}

	return config, nil
}

//GetToken function retrns cognito authorization token
//It opens new page with cognito UI for the google authorization
//If authorization was successfull it returns
func (c *CognitoAuth) GetToken() (*CognitoToken, error) {
	token := c.getTokenFromFile()
	if token != nil {
		log.Debug("Found valid token in the .token file")
		return token, nil
	}

	responseChan, errorChan := make(chan string), make(chan error)
	server := http.Server{Addr: fmt.Sprintf("localhost:%s", serverPort)}
	defer server.Close()
	go c.serveWebSocket(responseChan, errorChan)
	go c.serveAuthPage(errorChan, &server)
	err := openBrowser(fmt.Sprintf("http://localhost:%s", serverPort))
	if err != nil {
		return nil, fmt.Errorf("cannot open the Internet browser for authentication: %s", err.Error())
	}

	select {
	case err := <-errorChan:
		return nil, err
	case resp := <-responseChan:
		token := CognitoToken{
			Token:          resp,
			ExpirationDate: time.Now().Local().Add(time.Hour),
			auth:           c,
		}
		c.saveToken(token)
		return &token, nil
	}
}

func (c *CognitoAuth) hash() string {
	hash := md5.Sum([]byte(c.ClientID + c.UserPoolID + c.HostedUIDomain + c.Region))
	return fmt.Sprintf("%x", hash)
}

func (c *CognitoAuth) getTokenFromFile() *CognitoToken {
	fileName := c.getTokenPath()
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0660)
	if err != nil {
		return nil
	}

	b, err := ioutil.ReadAll(file)
	if err != nil {
		os.Remove(fileName)
		return nil
	}

	token := &CognitoToken{}
	err = json.Unmarshal(b, token)
	if err != nil {
		os.Remove(fileName)
		return nil
	}
	token.auth = c

	//Refresh token 2 minutes before expiration
	if token.ExpirationDate.Unix() < time.Now().Add(2*time.Minute).Unix() {
		os.Remove(fileName)
		return nil
	}

	return token
}

func (c *CognitoAuth) saveToken(token CognitoToken) {
	os.MkdirAll(filepath.Dir(c.getTokenPath()), os.ModePerm)
	file, err := os.OpenFile(c.getTokenPath(), os.O_WRONLY|os.O_CREATE, 0660)
	if err != nil {
		log.Warn("Failed to open or create file token", err.Error())
		return
	}

	data, _ := json.Marshal(token)
	err = file.Truncate(0)
	if err != nil {
		log.Warn("Failed to clear file token", err.Error())
		return
	}
	_, err = file.Write(data)
	if err != nil {
		log.Warn("Failed to write to file token", err.Error())
		return
	}
	file.Close()
}

func (c *CognitoAuth) getTokenPath() string {
	fileName := fmt.Sprintf(".token-%s", c.hash())
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return fileName
	}

	return filepath.Join(cacheDir, "cognito-cli-auth", fileName)
}

func (c *CognitoAuth) serveAuthPage(errorChan chan error, server *http.Server) {
	log.Debug(fmt.Sprintf("Serve web page localhost:%s", serverPort))
	t, static, err := getPageTemplate()
	if err != nil {
		log.Error("Failed to load auth page", err.Error())
		errorChan <- err
		return
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		err := t.Execute(w, *c)
		if err != nil {
			log.Error("Failed to serve auth page", err.Error())
			errorChan <- err
			server.Close()
		}
	}

	serverStatic := func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "cognitohosteduilauncher.js", time.Now(), bytes.NewReader(static))
	}

	http.HandleFunc("/", handler)
	http.HandleFunc("/cognitohosteduilauncher.js", serverStatic)
	server.ListenAndServe()
}

func (c *CognitoAuth) serveWebSocket(respChan chan string, errorChan chan error) {
	handler := func(ws *websocket.Conn) {
		var reply string
		if err := websocket.Message.Receive(ws, &reply); err != nil {
			log.Error("Failed to receive data from websocker", err.Error())
			errorChan <- err
			return
		}
		log.Debug("Received token from websocket")
		respChan <- reply
	}

	server := http.NewServeMux()
	log.Debug("Serve web socket localhost: 3001")
	server.Handle("/", websocket.Handler(handler))
	if err := http.ListenAndServe(":3001", server); err != nil {
		log.Error("ListenAndServe:", err)
		errorChan <- err
	}
}
