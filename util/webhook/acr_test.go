package webhook

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testACRSecret = "Bearer my-acr-secret"

func TestACRParser_CanHandle(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		url    string
		want   bool
	}{
		{"type=acr with secret", testACRSecret, "/api/webhook?type=acr", true},
		{"no type", testACRSecret, "/api/webhook", false},
		{"other type", testACRSecret, "/api/webhook?type=dockerhub", false},
		{"no secret configured", "", "/api/webhook?type=acr", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tt.url, strings.NewReader("{}"))
			assert.Equal(t, tt.want, newACRParser(tt.secret).CanHandle(req))
		})
	}
}

func TestACRParser_Parse(t *testing.T) {
	pushEvent, err := os.ReadFile("testdata/acr-push-event.json")
	require.NoError(t, err)

	tests := []struct {
		name     string
		method   string
		auth     string
		body     string
		wantErr  bool
		errIs    error
		expected *RegistryEvent
	}{
		{
			name:     "push event",
			auth:     testACRSecret,
			body:     string(pushEvent),
			expected: &RegistryEvent{RegistryURL: "myregistry.azurecr.io", Repository: "charts/mychart", Tag: "1.2.0"},
		},
		{name: "wrong secret", auth: "Bearer nope", body: string(pushEvent), wantErr: true, errIs: ErrSecretVerificationFailed},
		{name: "missing secret", body: string(pushEvent), wantErr: true, errIs: ErrSecretVerificationFailed},
		{name: "delete event skipped", auth: testACRSecret, body: `{"action":"delete","target":{"repository":"charts/mychart"},"request":{"host":"myregistry.azurecr.io"}}`},
		{name: "ping skipped", auth: testACRSecret, body: `{"action":"ping"}`},
		{name: "digest-only push skipped", auth: testACRSecret, body: `{"action":"push","target":{"repository":"charts/mychart"},"request":{"host":"myregistry.azurecr.io"}}`},
		{name: "non-POST rejected", method: http.MethodGet, auth: testACRSecret, body: string(pushEvent), wantErr: true},
		{name: "invalid JSON", auth: testACRSecret, body: "{", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequestWithContext(t.Context(), method, "/api/webhook?type=acr", strings.NewReader(tt.body))
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			got, err := newACRParser(testACRSecret).Parse(req)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errIs != nil {
					require.ErrorIs(t, err, tt.errIs)
				}
				return
			}
			require.NoError(t, err)
			if tt.expected == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

func TestACRPushEvent(t *testing.T) {
	hook := test.NewGlobal()
	h := NewMockHandlerWithACRSecret(testACRSecret, []string{})

	payload, err := os.ReadFile("testdata/acr-push-event.json")
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/webhook?type=acr", io.NopCloser(bytes.NewReader(payload)))
	req.Header.Set("Authorization", testACRSecret)
	w := httptest.NewRecorder()
	h.Handler(w, req)
	h.Shutdown()

	assert.Equal(t, http.StatusOK, w.Code)
	assertLogContains(t, hook, "Received registry webhook event")
}

// With no secret configured the parser claims nothing, so the request falls through
// to "Unknown webhook event" rather than reaching an unauthenticated endpoint.
func TestACRPushEvent_DisabledWithoutSecret(t *testing.T) {
	h := NewMockHandlerWithACRSecret("", []string{})

	payload, err := os.ReadFile("testdata/acr-push-event.json")
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/webhook?type=acr", io.NopCloser(bytes.NewReader(payload)))
	req.Header.Set("Authorization", testACRSecret)
	w := httptest.NewRecorder()
	h.Handler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestACRPushEvent_Unauthorized(t *testing.T) {
	h := NewMockHandlerWithACRSecret(testACRSecret, []string{})

	payload, err := os.ReadFile("testdata/acr-push-event.json")
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/webhook?type=acr", io.NopCloser(bytes.NewReader(payload)))
	req.Header.Set("Authorization", "Bearer wrong-secret")
	w := httptest.NewRecorder()
	h.Handler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
