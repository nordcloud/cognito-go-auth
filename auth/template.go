package auth

import (
	"fmt"
	"html/template"
	"os/exec"
	"runtime"

	log "github.com/sirupsen/logrus"
)

var templateBody = `
<!DOCTYPE html>
<html>
  <head>
    <script>
      var amplifyCognitoConfig = {
        region: "{{ .Region }}",
        userPoolId: "{{ .UserPoolID }}",
        userPoolWebClientId: "{{ .ClientID }}",
        redirectSignIn: "http://localhost:{{ .ServerPort }}",
        redirectSignOut: "http://localhost:{{ .ServerPort }}",
        domain: "{{ .HostedUIDomain }}"
      };
      var socket = "ws://localhost:3001";
    </script>
  </head>

  <body>
	<h1>Login process complete, you can now close the window</h1>
    <div id="app"></div>
    <script src="./cognitohosteduilauncher.js"></script>
  </body>
</html>`

func getPageTemplate() (*template.Template, []byte, error) {
	log.Debug("Building auth template")
	t := template.New("template.html")
	staticContect, err := Asset("cognitohosteduilauncher.js")
	if err != nil {
		log.Error("Failed load cognitohosteduilauncher.js file", err.Error())
		return nil, nil, err
	}

	t, err = t.Parse(templateBody)
	if err != nil {
		log.Error("Failed to parse template", err.Error())
		return nil, nil, err
	}
	return t, staticContect, nil
}

func openBrowser(url string) error {
	log.Debug("Opening browser")
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Run()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Run()
	case "darwin":
		return exec.Command("open", url).Run()
	default:
		return fmt.Errorf("unsupported platform")
	}
}
