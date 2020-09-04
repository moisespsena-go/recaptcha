// Package recaptcha handles reCaptcha (http://www.google.com/recaptcha) form submissions
//
// This package is designed to be called from within an HTTP server or web framework
// which offers reCaptcha form inputs and requires them to be evaluated for correctness
//
package recaptcha

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/moisespsena-go/maps"

	"github.com/pkg/errors"

	"github.com/moisespsena-go/middleware"
)

type ValidationFailedHandler func(w http.ResponseWriter, r *http.Request, err error)

type RecaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       float32   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

type ReCaptchaServerError struct {
	error
}

func (this ReCaptchaServerError) Err() error {
	return this.error
}

func (this ReCaptchaServerError) Error() string {
	return "recaptcha server error: " + this.error.Error()
}

const recaptchaServerName = "https://www.google.com/recaptcha/api/siteverify"

type ReCaptcha struct {
	PrivateKey  string
	Timeout     int8
	SkipFunc    func(r *http.Request) bool
	RealIPFunc  func(r *http.Request) string
	FailedFunc  ValidationFailedHandler
	MinScore    float32
	MaxFormSize int64
	Site        *Site
	Data        maps.Map
}

// New creates new ReCaptcha object for allows the webserver or code evaluating the reCaptcha form input to set the
// reCaptcha private key (string) value, which will be different for every domain.
func New(privateKey, publicKey string) *ReCaptcha {
	return &ReCaptcha{
		PrivateKey: privateKey,
		SkipFunc: func(r *http.Request) bool {
			return false
		},
		RealIPFunc: middleware.GetRealIP,
		Site:       NewSite(publicKey),
	}
}

// check uses the client ip address, the challenge code from the reCaptcha form,
// and the client's response input to that challenge to determine whether or not
// the client answered the reCaptcha input question correctly.
// It returns a boolean value indicating whether or not the client answered correctly.
func (this *ReCaptcha) check(remoteip, response string) (r RecaptchaResponse, err error) {
	var timeout = time.Duration(this.Timeout)
	if timeout == 0 {
		timeout = 4
	}
	var netTransport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout * time.Second,
	}
	var netClient = &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}

	resp, err := netClient.PostForm(recaptchaServerName,
		url.Values{"secret": {this.PrivateKey}, "remoteip": {remoteip}, "response": {response}})
	if err != nil {
		err = errors.New("Post error:" + err.Error())
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.New("Post error: could not read body: " + err.Error())
		return
	}
	err = json.Unmarshal(body, &r)
	if err != nil {
		err = errors.New("Read error: got invalid JSON: " + err.Error())
		return
	}
	return
}

// Confirm is the public interface function.
// It calls check, which the client ip address, the challenge code from the reCaptcha form,
// and the client's response input to that challenge to determine whether or not
// the client answered the reCaptcha input question correctly.
// It returns a boolean value indicating whether or not the client answered correctly.
func (this *ReCaptcha) Confirm(remoteip, response string) (ok bool, err error) {
	resp, err := this.check(remoteip, response)
	if err != nil {
		return
	}
	ok = resp.Success && (this.MinScore == 0 && resp.Score >= 0.7 || resp.Score >= this.MinScore)
	if !ok && len(resp.ErrorCodes) > 0 {
		err = errors.New(strings.Join(resp.ErrorCodes, ", "))
	}
	return
}

// ProcessRequest accepts the http.Request object, finds the reCaptcha form variables which
// were input and sent by HTTP POST to the server, then calls the recaptcha package's Confirm()
// method, which returns a boolean indicating whether or not the client answered the form correctly.
func (this *ReCaptcha) ProcessRequest(request *http.Request, realIP string) (result bool, err error) {
	recaptchaResponse, responseFound := request.Form["g-recaptcha-token"]
	if responseFound {
		var e2 error
		if result, e2 = this.Confirm(realIP, recaptchaResponse[0]); e2 != nil {
			err = ReCaptchaServerError{e2}
		}
	}
	return
}

func (this *ReCaptcha) FormCheck(w http.ResponseWriter, r *http.Request) (ok bool, err error) {
	if r.Method == "POST" && !this.SkipFunc(r) {
		realIP := this.RealIPFunc(r)
		if ok, err = this.ProcessRequest(r, realIP); !ok {
			return
		}
	}
	return true, nil
}

func (this *ReCaptcha) Validate(w http.ResponseWriter, r *http.Request) (ok bool, err error) {
	if strings.Contains(r.Host, "localhost") {
		return true, nil
	}
	if (r.Method == "POST" || r.Method == "PUT") && !this.SkipFunc(r) {
		if r.Form == nil {
			if err = middleware.ParseForm(r); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		var realIP = this.RealIPFunc(r)
		if ok, err = this.ProcessRequest(r, realIP); !ok {
			if err == nil {
				err = errors.New("google recaptcha token failed")
			}
			if this.FailedFunc != nil {
				this.FailedFunc(w, r, err)
			} else {
				http.Error(w, err.Error(), http.StatusPreconditionFailed)
				return
			}
			return
		}
	}
	return true, nil
}

func (this *ReCaptcha) Middleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := this.Validate(w, r); ok {
			next.ServeHTTP(w, r)
		}
	}
	return http.HandlerFunc(fn)
}
