package webhook

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/common"
)

// acrWebhookType is the value of the "type" query parameter that routes a request
// to the ACR parser. ACR sends no provider-specific header, so the user appends
// it to the webhook URL (e.g. /api/webhook?type=acr).
const acrWebhookType = "acr"

const acrEventPush = "push"

// acrPayload is the subset of an Azure Container Registry webhook payload needed
// to identify a pushed artifact.
// See https://learn.microsoft.com/en-us/azure/container-registry/container-registry-webhook-reference
type acrPayload struct {
	Action string `json:"action"`
	Target struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
	} `json:"target"`
	Request struct {
		Host string `json:"host"`
	} `json:"request"`
}

// acrParser parses Azure Container Registry webhook requests.
//
// ACR does not sign its payloads, but it can send custom headers. Requests are
// authenticated by comparing the Authorization header with webhook.acr.secret.
// An empty secret disables ACR webhook support.
type acrParser struct {
	secret string
}

func newACRParser(secret string) *acrParser {
	return &acrParser{secret: secret}
}

// CanHandle claims requests sent to /api/webhook?type=acr when a secret is configured.
func (p *acrParser) CanHandle(r *http.Request) bool {
	return p.secret != "" && r.URL.Query().Get("type") == acrWebhookType
}

// Parse checks the Authorization header and returns a *RegistryEvent for tagged
// push events. Other actions (delete, ping, chart_push...) return (nil, nil).
func (p *acrParser) Parse(r *http.Request) (any, error) {
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("unexpected method %q for ACR webhook", r.Method)
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(p.secret)) != 1 {
		log.WithField(common.SecurityField, common.SecurityHigh).Info("ACR webhook auth header mismatch")
		return nil, fmt.Errorf("%w: invalid ACR webhook Authorization header", ErrSecretVerificationFailed)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("acr webhook: failed to read request body: %w", err)
	}
	var payload acrPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("acr webhook: failed to parse payload: %w", err)
	}

	if payload.Action != acrEventPush || payload.Request.Host == "" || payload.Target.Repository == "" || payload.Target.Tag == "" {
		log.WithFields(log.Fields{
			"action":     payload.Action,
			"repository": payload.Target.Repository,
			"tag":        payload.Target.Tag,
		}).Debug("Skipping ACR webhook event")
		return nil, nil
	}

	return &RegistryEvent{
		RegistryURL: payload.Request.Host,
		Repository:  payload.Target.Repository,
		Tag:         payload.Target.Tag,
	}, nil
}
