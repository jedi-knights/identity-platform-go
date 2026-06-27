package http

import (
	"net/http"

	"github.com/jedi-knights/go-platform/httputil"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/application"
	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// MetadataHandler serves the RFC 8414 and OIDC Discovery 1.0 metadata
// documents per ADR-0012. The handler is split from the main /oauth
// handler so it has no dependencies on token storage or grant
// strategies — the metadata document is a pure function of running
// config, computed on every request so a hot-reload picks up
// immediately without restart logic in this layer.
type MetadataHandler struct {
	builder *application.MetadataBuilder
}

// NewMetadataHandler wires the handler around a [MetadataBuilder]. A
// nil builder panics — composition errors are loud at startup.
func NewMetadataHandler(builder *application.MetadataBuilder) *MetadataHandler {
	if builder == nil {
		panic("http: NewMetadataHandler called with nil builder")
	}
	return &MetadataHandler{builder: builder}
}

// OAuthMetadata serves GET /.well-known/oauth-authorization-server.
//
// @Summary      RFC 8414 metadata document
// @Description  Returns the OAuth 2.0 Authorization Server Metadata document
// @Tags         metadata
// @Produce      json
// @Success      200  {object}  domain.AuthorizationServerMetadata
// @Router       /.well-known/oauth-authorization-server [get]
func (h *MetadataHandler) OAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	h.writeMetadata(w, h.builder.OAuthMetadata())
}

// OIDCMetadata serves GET /.well-known/openid-configuration.
//
// @Summary      OIDC Discovery 1.0 metadata document
// @Description  Returns the OIDC discovery document
// @Tags         metadata
// @Produce      json
// @Success      200  {object}  domain.AuthorizationServerMetadata
// @Router       /.well-known/openid-configuration [get]
func (h *MetadataHandler) OIDCMetadata(w http.ResponseWriter, _ *http.Request) {
	h.writeMetadata(w, h.builder.OIDCMetadata())
}

// writeMetadata serialises the document as JSON with cache-friendly
// headers — the metadata is dynamic with respect to config but stable
// across many requests, so a one-hour public cache is a reasonable
// default. Clients that need fresher data can ignore the header per
// the standard HTTP cache rules.
func (h *MetadataHandler) writeMetadata(w http.ResponseWriter, body *domain.AuthorizationServerMetadata) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	httputil.WriteJSON(w, http.StatusOK, body)
}
