package authorizer

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/samlsp"
	"go.uber.org/zap"
)

// Config for Authorizer
type Config struct {
	EntityID            string
	URL                 string
	KeyFile             string
	CertificateFile     string
	AllowIDPInitiated   bool
	DefaultRedirectURI  string
	IDPMetadataURL      string
	SignRequest         bool
	UseArtifactResponse bool
	ForceAuthn          bool
	Addr                string
	RequireAttribute    []requirement
}

// AuthService authorizes users using SAML
type AuthService struct {
	SP                 samlsp.SessionProvider
	M                  *samlsp.Middleware
	RootURL            *url.URL
	RequiredAttributes []requirement
	Log                *zap.Logger
}

// Auth handler
func (s *AuthService) Auth(w http.ResponseWriter, r *http.Request) {
	attributes, err := s.getAttributes(r)
	if err != nil {
		s.httpError(w, r, http.StatusUnauthorized)
		return
	}

	// First check if we are allowed to process request
	if !s.checkACL(attributes) {
		s.httpError(w, r, http.StatusUnauthorized)
		return
	}

	// Second pass attributes as headers
	for name := range attributes {
		for _, v := range attributes[name] {
			w.Header().Add("X-"+name, v)
		}
	}

	s.httpStatus(w, r, http.StatusAccepted)
}

// Signin handler
func (s *AuthService) Signin(w http.ResponseWriter, r *http.Request) {
	attributes, err := s.getAttributes(r)
	if err != nil {
		if err == samlsp.ErrNoSession {
			// We expect most of the time to go here as this is signin handler
			s.startAuthFlow(w, r)
		} else {
			s.httpError(w, r, http.StatusInternalServerError)
		}
		return
	}

	// Not strictly necessary but for user convince we check ACL
	if !s.checkACL(attributes) {
		s.httpError(w, r, http.StatusForbidden)
		return
	}

	// User shouldnt end up here with valid session and all the permissions...
	s.httpError(w, r, http.StatusInternalServerError)
}

// Whoami handler
func (s *AuthService) Whoami(w http.ResponseWriter, r *http.Request) {
	attributes, err := s.getAttributes(r)
	if err != nil {
		s.httpError(w, r, http.StatusUnauthorized)
		return
	}

	s.httpStatus(w, r, http.StatusOK)
	for name := range attributes {
		for _, v := range attributes[name] {
			fmt.Fprintf(w, "%s: %s\n", name, v)
		}
	}
}

var errNoAttributes = errors.New("saml: attributes not present")

func (s *AuthService) getAttributes(r *http.Request) (samlsp.Attributes, error) {
	session, err := s.SP.GetSession(r)
	if err != nil {
		return nil, err
	}
	sa, ok := session.(samlsp.SessionWithAttributes)
	if !ok {
		return nil, errNoAttributes
	}
	return sa.GetAttributes(), nil
}

func (s *AuthService) startAuthFlow(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	rd := query.Get("rd")
	if rd == "" {
		// This is a configuration error
		s.httpError(w, r, http.StatusBadRequest)
		return
	}

	cleanURL, err := s.RootURL.Parse(rd)
	if err != nil {
		s.httpError(w, r, http.StatusInternalServerError)
		return
	}

	r.URL = cleanURL
	s.M.HandleStartAuthFlow(w, r)
}

func (s *AuthService) httpError(w http.ResponseWriter, r *http.Request, code int) {
	s.Log.Info("error response",
		zap.String("requestMethod", r.Method),
		zap.String("requestUrl", r.URL.String()),
		zap.String("userAgent", r.UserAgent()),
		zap.String("remoteIp", r.RemoteAddr),
		zap.Int("statusCode", code),
	)
	http.Error(w, http.StatusText(code), code)
}

func (s *AuthService) httpStatus(w http.ResponseWriter, r *http.Request, code int) {
	w.WriteHeader(code)
}

func (s *AuthService) checkACL(attributes samlsp.Attributes) bool {
	// Session with no attributes but configuration explicitly required some
	if len(attributes) == 0 && len(s.RequiredAttributes) > 0 {
		return false
	}
	// No required attributes so we can skip checking
	if len(s.RequiredAttributes) == 0 {
		return true
	}
	return aclCheckOR(attributes, s.RequiredAttributes)
}

type requirement map[string]string

func aclCheckOR(attributes samlsp.Attributes, requirements []requirement) bool {
	for _, r := range requirements {
		if aclCheckAND(attributes, r) {
			return true
		}
	}
	return false
}

func aclCheckAND(attributes samlsp.Attributes, r requirement) bool {
next:
	for name, want := range r {
		if values, ok := attributes[name]; ok {
			for _, got := range values {
				if got == want {
					continue next
				}
			}
		}
		return false
	}
	return true
}
