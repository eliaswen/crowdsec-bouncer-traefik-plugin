// Package captcha implements utility for captcha management.
package captcha

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"

	cache "github.com/eliaswen/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/eliaswen/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// Client Captcha client.
type Client struct {
	Valid                   bool
	siteKey                 string
	secretKey               string
	remediationCustomHeader string
	gracePeriodSeconds      int64
	templateContentType     string
	template                *template.Template
	cacheClient             *cache.Client
	httpClient              *http.Client
	log                     *slog.Logger
	infoProvider            *infoProvider
}

// Information for self-hosted provider.
type infoProvider struct {
	js       string
	key      string
	response string
	validate string
}

//nolint:gochecknoglobals
var infoProviders = map[string]*infoProvider{
	configuration.HcaptchaProvider: {
		js:       "https://hcaptcha.com/1/api.js",
		key:      "h-captcha",
		response: "h-captcha-response",
		validate: "https://api.hcaptcha.com/siteverify",
	},
	configuration.RecaptchaProvider: {
		js:       "https://www.google.com/recaptcha/api.js",
		key:      "g-recaptcha",
		response: "g-recaptcha-response",
		validate: "https://www.google.com/recaptcha/api/siteverify",
	},
	configuration.TurnstileProvider: {
		js:       "https://challenges.cloudflare.com/turnstile/v0/api.js",
		key:      "cf-turnstile",
		response: "cf-turnstile-response",
		validate: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	},
}

// New Initialize captcha client.
func (c *Client) New(log *slog.Logger, cacheClient *cache.Client, httpClient *http.Client, provider, js, key, response, validate, siteKey, secretKey, remediationCustomHeader, captchaTemplatePath string, gracePeriodSeconds int64) error {
	c.Valid = provider != ""
	if !c.Valid {
		return nil
	}
	var info *infoProvider
	if provider == configuration.CustomProvider {
		info = &infoProvider{js: js, key: key, response: response, validate: validate}
	} else {
		info = infoProviders[provider]
	}
	c.infoProvider = info
	c.siteKey = siteKey
	c.secretKey = secretKey
	c.remediationCustomHeader = remediationCustomHeader
	template, contentType, _ := configuration.GetTemplate(captchaTemplatePath)
	c.template = template
	c.templateContentType = contentType
	c.gracePeriodSeconds = gracePeriodSeconds
	c.log = log
	c.httpClient = httpClient
	c.cacheClient = cacheClient
	return nil
}

// ServeHTTP Handle captcha html page or validation.
func (c *Client) ServeHTTP(rw http.ResponseWriter, r *http.Request, remoteIP string) {
	c.ServeHTTPWithData(rw, r, remoteIP, nil)
}

// ServeHTTPWithData renders the captcha with decision metadata supplied by the
// middleware while preserving ServeHTTP for existing integrations.
func (c *Client) ServeHTTPWithData(rw http.ResponseWriter, r *http.Request, remoteIP string, decisionData map[string]string) {
	valid, err := c.Validate(r)
	if err != nil {
		c.log.Info("captcha:ServeHTTP:validate " + err.Error())
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	if valid {
		c.log.Debug("captcha:ServeHTTP captcha:valid")
		c.cacheClient.Set(remoteIP+"_captcha", cache.CaptchaDoneValue, c.gracePeriodSeconds)
		if c.remediationCustomHeader != "" {
			rw.Header().Set(c.remediationCustomHeader, "solved-captcha")
		}
		http.Redirect(rw, r, r.URL.String(), http.StatusFound)
		return
	}
	rw.Header().Set("Content-Type", c.templateContentType)
	if c.remediationCustomHeader != "" {
		rw.Header().Set(c.remediationCustomHeader, "captcha")
	}
	rw.WriteHeader(http.StatusOK)
	templateData := map[string]string{
		"SiteKey":                   c.siteKey,
		"FrontendJS":                c.infoProvider.js,
		"FrontendKey":               c.infoProvider.key,
		"CaptchaGracePeriodSeconds": strconv.FormatInt(c.gracePeriodSeconds, 10),
		"CaptchaGracePeriod":        readableDuration(c.gracePeriodSeconds),
	}
	for key, value := range decisionData {
		templateData[key] = value
	}
	err = c.template.Execute(rw, templateData)
	if err != nil {
		c.log.Info("captcha:ServeHTTP captchaTemplateServe " + err.Error())
	}
}

func readableDuration(seconds int64) string {
	parts := make([]string, 0, 3)
	for _, unit := range []struct {
		name    string
		seconds int64
	}{{"hour", 3600}, {"minute", 60}, {"second", 1}} {
		value := seconds / unit.seconds
		seconds %= unit.seconds
		if value > 0 || (unit.seconds == 1 && len(parts) == 0) {
			name := unit.name
			if value != 1 {
				name += "s"
			}
			parts = append(parts, fmt.Sprintf("%d %s", value, name))
		}
	}
	return strings.Join(parts, " ")
}

// Check Verify if the captcha is already done.
func (c *Client) Check(remoteIP string) bool {
	value, _ := c.cacheClient.Get(remoteIP + "_captcha")
	passed := value == cache.CaptchaDoneValue
	c.log.Debug(fmt.Sprintf("captcha:Check ip:%s pass:%v", remoteIP, passed))
	return passed
}

type responseProvider struct {
	Success bool `json:"success"`
}

// Validate Verify the captcha from provider API.
func (c *Client) Validate(r *http.Request) (bool, error) {
	if r.Method != http.MethodPost {
		c.log.Debug("captcha:Validate invalid method: " + r.Method)
		return false, nil
	}
	var response = r.FormValue(c.infoProvider.response)
	if response == "" {
		c.log.Debug("captcha:Validate no captcha response found in request")
		return false, nil
	}
	var body = url.Values{}
	body.Add("secret", c.secretKey)
	body.Add("response", response)
	res, err := c.httpClient.PostForm(c.infoProvider.validate, body)
	if err != nil {
		return false, err
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			c.log.Error("captcha:Validate " + err.Error())
		}
	}()
	if !strings.Contains(res.Header.Get("Content-Type"), "application/json") {
		c.log.Debug("captcha:Validate responseType:noJson")
		return false, nil
	}
	var captchaResponse responseProvider
	err = json.NewDecoder(res.Body).Decode(&captchaResponse)
	if err != nil {
		return false, err
	}
	c.log.Debug(fmt.Sprintf("captcha:Validate success:%v", captchaResponse.Success))
	return captchaResponse.Success, nil
}
