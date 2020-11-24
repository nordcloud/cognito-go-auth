package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/nordcloud/cognito-go-auth/auth"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	method  string
	headers []string
	body    string

	clientID string
	domain   string
	verbose  bool
)

func printResponse(resp *http.Response) {
	resBytes, _ := ioutil.ReadAll(resp.Body)
	if verbose {
		fmt.Println("Status Code: ", resp.StatusCode)
		fmt.Println("Response headers: ")
		for key, val := range (map[string][]string)(resp.Header) {
			if len(val) == 1 {
				fmt.Printf("\t%s: %v\n", key, val[0])
			} else {
				fmt.Printf("\t%s: %v\n", key, val)
			}
		}
	}
	fmt.Println("\n", string(resBytes))
}

func setHeaders(req *http.Request, headers []string) *http.Request {
	for _, h := range headers {
		hh := strings.SplitN(h, ":", 2)
		if len(hh) != 2 {
			log.Warn("Incorrect request header ", h)
			continue
		}
		req.Header[hh[0]] = []string{strings.Trim(hh[1], " ")}
	}
	return req
}

var rootCmd = &cobra.Command{
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			log.Error("Missing request URL")
			return
		}

		authorizer := auth.Auth0{
			ClientID: clientID,
			Domain:   domain,
		}

		req, err := http.NewRequest(method, args[0], strings.NewReader(body))
		if err != nil {
			log.Error("Failed to create request")
			return
		}
		req.Header["Content-Type"] = []string{"application/json"}
		req = setHeaders(req, headers)
		client := &http.Client{}

		var resp *http.Response
		for i := 0; i < 2; i++ {
			token, err := authorizer.GetToken()
			if err != nil {
				log.WithError(err).Error("Failed to generate authorization token")
				return
			}
			req = token.Sign(req)

			resp, err = client.Do(req)
			if err != nil {
				log.Error("Failed to make request", err.Error())
				return
			}
			if resp.StatusCode == 401 {
				token.Invalidate()
			} else {
				break
			}
		}
		printResponse(resp)
	},
}

func main() {
	log.SetLevel(log.InfoLevel)
	rootCmd.PersistentFlags().StringVarP(&method, "request", "X", "GET", "Request method")
	rootCmd.PersistentFlags().StringVarP(&body, "data", "d", "", "Request method")
	rootCmd.PersistentFlags().StringArrayVarP(&headers, "header", "H", []string{}, "Request header 'HeaderName: HeaderValue' ")

	rootCmd.PersistentFlags().StringVarP(&clientID, "client-id", "c", "", "AWS cognito Client ID")
	rootCmd.PersistentFlags().StringVarP(&domain, "domain", "u", "", "Addres of the hosted UI")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Show response headers and status code")
	rootCmd.Execute()
}
