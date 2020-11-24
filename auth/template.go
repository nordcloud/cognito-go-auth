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
  <body>
	<h1>Login process complete, you can now close this window</h1>
    <div id="app"></div>
  </body>
</html>`

func getPageTemplate() (*template.Template, error) {
	log.Debug("Building auth template")
	t := template.New("template.html")

	t, err := t.Parse(templateBody)
	if err != nil {
		log.Error("Failed to parse template", err.Error())
		return nil, err
	}
	return t, nil
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
