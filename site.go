package recaptcha

import (
	"net/http"
	"strings"

	"github.com/ecletus/core/utils"
)

type Site struct {
	Key string
	uri string
}

func NewSite(key string) *Site {
	return &Site{Key: key, uri: "https://www.google.com/recaptcha/api.js?render=" + key}
}

func (this *Site) HeaderScript() string {
	return `<script type="text/javascript" src="https://www.google.com/recaptcha/api.js?render=` + this.Key + `"></script>`
}

func (this *Site) HeaderStyle() string {
	return loaderCss()
}

func (this *Site) Script(action string, form string) string {
	var pos = strings.Index(form, "</form>")
	id := `g-recaptcha__` + utils.ToParamString(strings.ReplaceAll(action, "/", "--"))
	form = form[0:pos] + `<input id="` + id + `" type="hidden" name="g-recaptcha-token" />` + form[pos:]
	return form +
		`<script type="text/javascript">
function grecaptcha_execute() {
	grecaptcha.execute('` + this.Key + `', {action: '` + action + `'})
		.then(function(token) {
    		var el = document.getElementById("` + id + `");
			el.value = token;
		})
}
window.addEventListener("load", function(){
	grecaptcha_execute();
	setInterval(function(){grecaptcha_execute()}, 114000);
})
</script>`
}

func MiddlewareContext(key interface{}, failed ValidationFailedHandler, next http.Handler) http.Handler {
	if failed == nil {
		failed = DefaultValidateFailedHandler
	}
	fn := func(w http.ResponseWriter, r *http.Request) {
		if ok, err := ValidateContext(key, w, r); !ok {
			failed(w, r, err)
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func ValidateContext(key interface{}, w http.ResponseWriter, r *http.Request) (ok bool, err error) {
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		if ReCaptchaI := r.Context().Value(key); ReCaptchaI != nil {
			ReCaptcha := ReCaptchaI.(*ReCaptcha)
			ok, err = ReCaptcha.Validate(w, r)
		}
	}
	return
}

func Interceptor(key interface{}) func(w http.ResponseWriter, r *http.Request) (ok bool, err error) {
	return func(w http.ResponseWriter, r *http.Request) (ok bool, err error) {
		return ValidateContext(key, w, r)
	}
}

func DefaultValidateFailedHandler(w http.ResponseWriter, r *http.Request, err error) {
	var reason string
	if err != nil {
		reason += ": " + err.Error()
	}
	http.Error(w, "recaptcha validation failed"+reason, http.StatusBadRequest)
}
