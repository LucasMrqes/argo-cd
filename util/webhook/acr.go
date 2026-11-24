package webhook

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	// acrWebhookType is the value of the "type" query parameter that identifies
	// an incoming request as an Azure Container Registry webhook. ACR sends no
	// provider-specific header, so the user appends this to the configured webhook
	// URL (e.g. /api/webhook?type=acr) to route the request to this parser.
	acrWebhookType = "acr"

	// acrEventPush is the ACR webhook action for an image or artifact push.
	acrEventPush = "push"
)

// acrParser parses webhook payloads sent by Azure Container Registry (ACR).
//
// It extracts artifact push events from ACR registry webhooks and converts them
// into a normalized RegistryEvent. ACR neither signs its payloads nor sends a
// distinguishing header, so requests are claimed via a query parameter (see
// acrWebhookType) and authenticated with a shared secret carried in the
// Authorization header, which ACR can send as a custom header.
//
// Configuring the secret is required: an empty secret disables ACR webhook
// support entirely rather than leaving an unauthenticated endpoint that anyone can
// flood with refresh-triggering requests.
type acrParser struct {
	secret string
}

// acrPayload represents the subset of the webhook payload ACR sends for push
// events that we need to identify the pushed artifact.
// See https://learn.microsoft.com/en-us/azure/container-registry/container-registry-webhook-reference.
type acrPayload struct {
	// Action is the event type, e.g. "push", "delete", "quarantine", "chart_push", "chart_delete".
	Action string `json:"action"`
	Target struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
	} `json:"target"`
	Request struct {
		// Host is the registry login server, e.g. "myregistry.azurecr.io".
		Host string `json:"host"`
	} `json:"request"`
}

// newACRParser creates a new acrParser instance.
//
// ACR cannot sign webhook payloads, so the parser authenticates requests using a
// shared secret supplied in the Authorization header. When secret is empty the
// parser refuses all requests via CanHandle, which disables ACR webhook support.
func newACRParser(secret string) *acrParser {
	if secret == "" {
		log.Warn("ACR webhook secret is not configured; ACR webhook support is disabled")
	}
	return &acrParser{
		secret: secret,
	}
}

// CanHandle reports whether the HTTP request corresponds to an ACR webhook.
//
// ACR does not set a provider-specific header (unlike GitHub's X-GitHub-Event),
// so the request is identified by the "type=acr" query parameter the user adds to
// the configured webhook URL. If no secret is configured this always returns
// false, disabling ACR webhook support so that the endpoint is never reachable
// without authentication.
func (p *acrParser) CanHandle(r *http.Request) bool {
	if p.secret == "" {
		return false
	}
	return r.URL.Query().Get("type") == acrWebhookType
}

// Parse validates the request and extracts artifact push details from an ACR
// webhook payload.
//
// It rejects non-POST requests, verifies the shared secret, and returns a
// normalized RegistryEvent containing the registry host (taken from
// request.host), repository, and pushed tag. It returns nil, nil for events that
// are intentionally skipped (non-push actions such as delete or ping, and
// digest-only pushes) and an error only for malformed payloads or a failed
// secret check.
func (p *acrParser) Parse(r *http.Request) (any, error) {
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("unexpected method %q for ACR webhook", r.Method)
	}
	if err := p.validateSecret(r); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("acr webhook: failed to read request body: %w", err)
	}
	// Log the payload size only, never the body itself: it is request-controlled
	// and a misrouted request could carry sensitive data we don't want in logs.
	log.WithField("bytes", len(body)).Debug("Parsing ACR webhook payload")
	var payload acrPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ACR webhook payload: %w", err)
	}

	if payload.Action != acrEventPush {
		log.WithField("action", payload.Action).Debug("Skipping ACR webhook event: not a push event")
		return nil, nil
	}
	if payload.Request.Host == "" || payload.Target.Repository == "" || payload.Target.Tag == "" {
		log.WithFields(log.Fields{
			"registry":   payload.Request.Host,
			"repository": payload.Target.Repository,
			"tag":        payload.Target.Tag,
		}).Debug("Skipping ACR webhook event: missing registry, repository or tag")
		return nil, nil
	}

	log.WithFields(log.Fields{
		"registry":   payload.Request.Host,
		"repository": payload.Target.Repository,
		"tag":        payload.Target.Tag,
	}).Info("Parsed ACR webhook push event")

	return &RegistryEvent{
		RegistryURL: payload.Request.Host,
		Repository:  payload.Target.Repository,
		Tag:         payload.Target.Tag,
	}, nil
}

// validateSecret verifies the shared secret carried in the Authorization header.
//
// ACR does not support signing webhook payloads, but it can send custom headers,
// so the secret is compared in constant time against the Authorization header,
// matching how the Harbor parser authenticates. Unlike Docker Hub, there is no
// query parameter fallback: ACR can set the header itself, which keeps the secret
// out of URLs and access logs.
//
// A mismatch returns ErrSecretVerificationFailed, which the handler maps to an HTTP
// 401 response. An unconfigured secret cannot reach this point, because CanHandle
// already refuses every request in that case.
func (p *acrParser) validateSecret(r *http.Request) error {
	if p.secret == "" {
		return fmt.Errorf("%w: ACR webhook secret is not configured", ErrSecretVerificationFailed)
	}
	provided := r.Header.Get("Authorization")
	if subtle.ConstantTimeCompare([]byte(provided), []byte(p.secret)) != 1 {
		// Never log the secret values; logging whether one was supplied is enough
		// to distinguish "no secret sent" from "wrong value".
		log.WithField("secretProvided", provided != "").Debug("ACR webhook secret validation failed")
		return fmt.Errorf("%w: invalid ACR webhook secret", ErrSecretVerificationFailed)
	}
	return nil
}
