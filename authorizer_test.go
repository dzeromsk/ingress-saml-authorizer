package authorizer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"go.uber.org/zap"
)

func fakeAuthService(sp samlsp.SessionProvider, r []requirement) *AuthService {
	rootURL, _ := url.Parse("http://example.com")
	return &AuthService{
		SP: sp,
		M: &samlsp.Middleware{
			ServiceProvider: saml.ServiceProvider{
				IDPMetadata: &saml.EntityDescriptor{
					IDPSSODescriptors: []saml.IDPSSODescriptor{{
						SingleSignOnServices: []saml.Endpoint{{
							Binding:  saml.HTTPRedirectBinding,
							Location: "/example",
						}},
					}},
				},
			},
			Binding:        saml.HTTPRedirectBinding,
			RequestTracker: &fakeRequestTracker{},
			// Session:     sp,
		},
		RequiredAttributes: r,
		RootURL:            rootURL,
		Log:                zap.NewNop(),
	}
}

func TestAuthHandlerWithoutSession(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/auth", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&unknownUser{}, nil)

	s.Auth(res, req)

	got, want := res.Code, http.StatusUnauthorized
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestAuthHandlerNoPermissions(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/auth", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&validUser{}, []requirement{{
		"group": "admins",
	}})

	s.Auth(res, req)

	got, want := res.Code, http.StatusUnauthorized
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestAuthHandlerSuccess(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/auth", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&validUser{}, []requirement{{
		"groupX": "admins",
	}, {
		"name": "Alice", // match
	}, {
		"name": "Bob",
	}})

	s.Auth(res, req)

	got, want := res.Code, http.StatusAccepted
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}

	header, expect := res.Header().Get("X-Name"), "Alice"
	if header != expect {
		t.Errorf("got header X-Name %s but wanted %s", header, expect)
	}
}

func TestSigninHandlerWithoutSession(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/signin?rd=%2F", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&unknownUser{}, nil)

	s.Signin(res, req)

	got, want := res.Code, http.StatusFound
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}

	location := res.Header().Get("Location")
	if !strings.HasPrefix(location, "/example?SAMLRequest=") {
		t.Errorf("got location %.21s... but wanted /example?SAMLRequest=...", location)
	}
}

func TestSigninHandlerWithoutSessionMissingRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/signin", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&unknownUser{}, nil)

	s.Signin(res, req)

	got, want := res.Code, http.StatusBadRequest
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestSigninHandlerInvalidUser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/signin?rd=%2F", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&invalidUser{}, nil)

	s.Signin(res, req)

	got, want := res.Code, http.StatusInternalServerError
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestSigninHandlerAlreadyLoggedIn(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/signin?rd=%2F", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&validUser{}, nil)

	s.Signin(res, req)

	got, want := res.Code, http.StatusInternalServerError
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestSigninHandlerLoggedInButNoPermissions(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/signin?rd=%2F", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&validUser{}, []requirement{{
		"group": "admins",
	}})

	s.Signin(res, req)

	got, want := res.Code, http.StatusForbidden
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestWhoamiHandlerWithoutSession(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/whoami", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&unknownUser{}, nil)

	s.Whoami(res, req)

	got, want := res.Code, http.StatusUnauthorized
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestWhoamiHandlerWithAttributes(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/whoami", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&validUser{}, nil)

	s.Whoami(res, req)

	got, want := res.Code, http.StatusOK
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestStartAuthFlowWithoutRedirectURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/signin", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&unknownUser{}, nil)

	s.startAuthFlow(res, req)

	got, want := res.Code, http.StatusBadRequest
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestStartAuthFlowWithWrongRedirectURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/signin?rd=::", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&unknownUser{}, nil)

	s.startAuthFlow(res, req)

	got, want := res.Code, http.StatusInternalServerError
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}
}

func TestStartAuthFlowSuccess(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/signin?rd=%2F", nil)
	res := httptest.NewRecorder()

	s := fakeAuthService(&unknownUser{}, nil)

	s.startAuthFlow(res, req)

	got, want := res.Code, http.StatusFound
	if got != want {
		t.Errorf("got status %d but wanted %d", got, want)
	}

	location := res.Header().Get("Location")
	if !strings.HasPrefix(location, "/example?SAMLRequest=") {
		t.Errorf("got location %.21s... but wanted /example?SAMLRequest=...", location)
	}
}

func TestGetAttributes(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		service *AuthService
		args    args
		want    samlsp.Attributes
		wantErr bool
	}{{
		name:    "ValidUserShouldPass",
		service: fakeAuthService(&validUser{}, nil),
		want: samlsp.Attributes{
			"name":  []string{"Alice"},
			"email": []string{"alice@example.com"},
			"group": []string{"users"},
		},
		wantErr: false,
	}, {
		name:    "UnknownUserShouldFail",
		service: fakeAuthService(&unknownUser{}, nil),
		wantErr: true,
	}, {
		name:    "UserWithoutAttributesShouldFail",
		service: fakeAuthService(&noattrUser{}, nil),
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.service.getAttributes(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("authService.getAttributes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authService.getAttributes() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestCheckACL(t *testing.T) {
	type fields struct {
		sp                 samlsp.SessionProvider
		m                  *samlsp.Middleware
		rootURL            *url.URL
		requiredAttributes []requirement
		log                *zap.Logger
	}
	type args struct {
		attributes samlsp.Attributes
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{{
		name: "RequireAttrButNoAttrShouldFail",
		fields: fields{
			requiredAttributes: []requirement{{
				"name": "Alice",
			}},
		},
		args: args{
			attributes: samlsp.Attributes{},
		},
		want: false,
	}, {
		name: "EmptyAttrShouldPass",
		fields: fields{
			requiredAttributes: nil,
		},
		args: args{
			attributes: samlsp.Attributes{
				"name":  []string{"Alice"},
				"email": []string{"alice@example.com"},
			},
		},
		want: true,
	}, {
		name: "MatchAttrShouldPass",
		fields: fields{
			requiredAttributes: []requirement{{
				"name": "Alice",
			}},
		},
		args: args{
			attributes: samlsp.Attributes{
				"name":  []string{"Alice"},
				"email": []string{"alice@example.com"},
			},
		},
		want: true,
	}, {
		name: "FailAttrCheckShouldFail",
		fields: fields{
			requiredAttributes: []requirement{{
				"name": "Bob",
			}},
		},
		args: args{
			attributes: samlsp.Attributes{
				"name":  []string{"Alice"},
				"email": []string{"alice@example.com"},
			},
		},
		want: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &AuthService{
				SP:                 tt.fields.sp,
				M:                  tt.fields.m,
				RootURL:            tt.fields.rootURL,
				RequiredAttributes: tt.fields.requiredAttributes,
				Log:                tt.fields.log,
			}
			if got := s.checkACL(tt.args.attributes); got != tt.want {
				t.Errorf("authService.checkACL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAclCheckOR(t *testing.T) {
	type args struct {
		attributes   samlsp.Attributes
		requirements []requirement
	}
	tests := []struct {
		name string
		args args
		want bool
	}{{
		name: "MultipleAttrOneFalseReqShouldFail",
		args: args{
			attributes: samlsp.Attributes{
				"name":  []string{"Alice"},
				"email": []string{"alice@example.com"},
			},
			requirements: []requirement{{
				"name": "Bob",
			}},
		},
		want: false,
	}, {
		name: "MultipleAttrOneReqShouldPass",
		args: args{
			attributes: samlsp.Attributes{
				"name":  []string{"Alice"},
				"email": []string{"alice@example.com", "alice@example.org"},
			},
			requirements: []requirement{{
				"email": "alice@example.com",
			}},
		},
		want: true,
	}, {
		name: "MultipleAttrMultipleFalseReqShouldFail",
		args: args{
			attributes: samlsp.Attributes{
				"name":  []string{"Alice"},
				"email": []string{"alice@example.com", "alice@example.org"},
			},
			requirements: []requirement{{
				"name":  "Alice",
				"email": "alice@example.org",
				"sn":    "Doe",
			}, {
				"name":  "Bob",
				"email": "alice@example.org",
			}, {
				"name": "Carol",
			}, {
				"undefined": "...",
			}},
		},
		want: false,
	}, {
		name: "MultipleAttrMultipleReqShouldPass",
		args: args{
			attributes: samlsp.Attributes{
				"name":  []string{"Carol"},
				"email": []string{"carol@example.com", "carol@example.org"},
			},
			requirements: []requirement{{
				"name":  "Alice",
				"email": "alice@example.org",
			}, {
				"name":  "Carol",
				"email": "carol@example.org",
				"sn":    "Doe",
			}, {
				"email": "carol@example.org", // valid
			}},
		},
		want: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aclCheckOR(tt.args.attributes, tt.args.requirements); got != tt.want {
				t.Errorf("aclCheckOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAclCheckAND(t *testing.T) {
	type args struct {
		attributes samlsp.Attributes
		r          requirement
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "OneAttrOneReqShouldPass",
			args: args{
				attributes: samlsp.Attributes{
					"name": []string{"Alice"},
				},
				r: requirement{
					"name": "Alice",
				},
			},
			want: true,
		},
		{
			name: "OneAttrOneFalseReqShouldFail",
			args: args{
				attributes: samlsp.Attributes{
					"name": []string{"Alice"},
				},
				r: requirement{
					"name": "Bob",
				},
			},
			want: false,
		},
		{
			name: "MultipleAttrOneFalseReqShouldFail",
			args: args{
				attributes: samlsp.Attributes{
					"name":  []string{"Alice"},
					"email": []string{"alice@example.com"},
				},
				r: requirement{
					"name": "Bob",
				},
			},
			want: false,
		},
		{
			name: "MultipleAttrOneFalseReqShouldPass",
			args: args{
				attributes: samlsp.Attributes{
					"name":  []string{"Alice"},
					"email": []string{"alice@example.com", "alice@example.org"},
				},
				r: requirement{
					"email": "alice@example.com",
				},
			},
			want: true,
		},
		{
			name: "MultipleAttrMultipleFalseReqShouldFail",
			args: args{
				attributes: samlsp.Attributes{
					"name":  []string{"Alice"},
					"email": []string{"alice@example.com", "alice@example.org"},
				},
				r: requirement{
					"name":  "Bob",
					"email": "alice@example.org",
				},
			},
			want: false,
		},
		{
			name: "MultipleAttrMultipleReqShouldPass",
			args: args{
				attributes: samlsp.Attributes{
					"name":  []string{"Alice"},
					"email": []string{"alice@example.com", "alice@example.org"},
				},
				r: requirement{
					"name":  "Alice",
					"email": "alice@example.org",
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aclCheckAND(tt.args.attributes, tt.args.r); got != tt.want {
				t.Errorf("aclCheckAND() = %v, want %v", got, tt.want)
			}
		})
	}
}

type invalidUser struct{}

func (u *invalidUser) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	return nil
}
func (u *invalidUser) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	return nil
}
func (u *invalidUser) GetSession(r *http.Request) (samlsp.Session, error) {
	return nil, errors.New("invalid")
}

type unknownUser struct{}

func (u *unknownUser) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	return nil
}
func (u *unknownUser) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	return nil
}
func (u *unknownUser) GetSession(r *http.Request) (samlsp.Session, error) {
	return nil, samlsp.ErrNoSession
}

type noattrUser struct{}

func (u *noattrUser) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	return nil
}
func (u *noattrUser) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	return nil
}
func (u *noattrUser) GetSession(r *http.Request) (samlsp.Session, error) {
	return &sessionWithoutAttributes{}, nil
}

type validUser struct{}

func (u *validUser) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	return nil
}
func (u *validUser) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	return nil
}
func (u *validUser) GetSession(r *http.Request) (samlsp.Session, error) {
	return &sessionWithAttributes{}, nil
}

type sessionWithoutAttributes struct{}

type sessionWithAttributes struct{}

func (s *sessionWithAttributes) GetAttributes() samlsp.Attributes {
	return samlsp.Attributes{
		"name":  []string{"Alice"},
		"email": []string{"alice@example.com"},
		"group": []string{"users"},
	}
}

type fakeRequestTracker struct{}

func (t *fakeRequestTracker) TrackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string) (index string, err error) {
	return "index", nil
}

func (t *fakeRequestTracker) StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error {
	return nil
}

func (t *fakeRequestTracker) GetTrackedRequests(r *http.Request) []samlsp.TrackedRequest {
	return nil
}

func (t *fakeRequestTracker) GetTrackedRequest(r *http.Request, index string) (*samlsp.TrackedRequest, error) {
	return nil, nil
}
