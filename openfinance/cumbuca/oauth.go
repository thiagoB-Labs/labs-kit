// Package cumbuca é o adapter do Open Finance Data MCP da Cumbuca (docs/adr/0002).
//
// Confirmado (metadata público, 2026-11-08): OAuth 2 num Keycloak (realm cumbuca-mcp) com
// registro dinâmico de cliente, PKCE S256 e escopo offline_access; o recurso MCP fala
// Streamable HTTP com Bearer. A confirmar com uma conexão real (issue E01): nomes e schemas
// das tools. Por isso as tools são descobertas em tools/list e o resultado é lido pelo padrão de
// dados do Open Finance Brasil; qualquer formato inesperado vira provedor.ErrResposta (a
// sincronização é cancelada e alertada, nunca grava dado adivinhado).
package cumbuca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	provedor "github.com/thiagoB-Labs/labs-kit/openfinance"
)

// Config do adapter.
type Config struct {
	Issuer       string // https://idc.cumbuca.com/realms/cumbuca-mcp
	MCPURL       string // https://mcp.cumbuca.com/mcp
	ClientID     string
	ClientSecret string
	Scopes       string
	// NomeCliente vai no clientInfo do initialize do MCP (padrão "labs-kit").
	NomeCliente string
	HTTP        *http.Client
	Agora       func() time.Time
}

// Cumbuca implementa provedor.Provedor.
type Cumbuca struct {
	cfg   Config
	tools *catalogo
}

// New cria o adapter.
func New(c Config) *Cumbuca {
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if c.Agora == nil {
		c.Agora = time.Now
	}
	if c.NomeCliente == "" {
		c.NomeCliente = "labs-kit"
	}
	return &Cumbuca{cfg: c, tools: &catalogo{}}
}

// Nome implementa provedor.Provedor.
func (c *Cumbuca) Nome() string { return "cumbuca" }

func (c *Cumbuca) endpoint(p string) string {
	return c.cfg.Issuer + "/protocol/openid-connect/" + p
}

// recurso é o identificador do recurso protegido (RFC 8707).
func (c *Cumbuca) recurso() string {
	u, err := url.Parse(c.cfg.MCPURL)
	if err != nil {
		return c.cfg.MCPURL
	}
	return u.Scheme + "://" + u.Host
}

// URLAutorizacao implementa provedor.Provedor.
func (c *Cumbuca) URLAutorizacao(_ context.Context, p provedor.PedidoAutorizacao) (string, error) {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {p.RedirectURI},
		"scope":                 {c.cfg.Scopes},
		"state":                 {p.State},
		"code_challenge":        {p.CodeChallenge},
		"code_challenge_method": {"S256"},
		"resource":              {c.recurso()},
	}
	return c.endpoint("auth") + "?" + q.Encode(), nil
}

type respostaToken struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Erro             string `json:"error"`
}

// TrocarCodigo implementa provedor.Provedor.
func (c *Cumbuca) TrocarCodigo(ctx context.Context, code, verifier, redirectURI string) (provedor.Tokens, error) {
	return c.token(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {c.recurso()}}, "")
}

// Renovar implementa provedor.Provedor. O refresh token pode ser rotacionado.
func (c *Cumbuca) Renovar(ctx context.Context, t provedor.Tokens) (provedor.Tokens, error) {
	if t.Refresh == "" {
		return provedor.Tokens{}, provedor.ErrConsentimento
	}
	return c.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t.Refresh}}, t.Refresh)
}

func (c *Cumbuca) token(ctx context.Context, form url.Values, refreshAnterior string) (provedor.Tokens, error) {
	var r respostaToken
	st, h, err := c.postForm(ctx, c.endpoint("token"), form, &r)
	if err != nil {
		return provedor.Tokens{}, err
	}
	switch {
	case st == http.StatusTooManyRequests:
		return provedor.Tokens{}, limite(h)
	case st >= 500:
		return provedor.Tokens{}, fmt.Errorf("%w: token HTTP %d", provedor.ErrTransitorio, st)
	case st == http.StatusBadRequest && r.Erro == "access_denied":
		return provedor.Tokens{}, provedor.ErrNegado
	case st == http.StatusBadRequest || st == http.StatusUnauthorized:
		// invalid_grant: código usado/expirado, refresh revogado ou consentimento encerrado.
		return provedor.Tokens{}, fmt.Errorf("%w: %s", provedor.ErrConsentimento, r.Erro)
	case st != http.StatusOK || r.AccessToken == "":
		return provedor.Tokens{}, fmt.Errorf("%w: token HTTP %d", provedor.ErrResposta, st)
	}
	agora := c.cfg.Agora()
	t := provedor.Tokens{Access: r.AccessToken, Refresh: r.RefreshToken, AccessExpira: agora.Add(time.Duration(r.ExpiresIn) * time.Second)}
	if r.ExpiresIn <= 0 {
		t.AccessExpira = agora.Add(5 * time.Minute)
	}
	if t.Refresh == "" {
		t.Refresh = refreshAnterior
	}
	if r.RefreshExpiresIn > 0 {
		t.RefreshExpira = agora.Add(time.Duration(r.RefreshExpiresIn) * time.Second)
	}
	return t, nil
}

// Revogar implementa provedor.Provedor (RFC 7009): revoga o refresh token, que derruba a sessão.
func (c *Cumbuca) Revogar(ctx context.Context, t provedor.Tokens) error {
	tok, hint := t.Refresh, "refresh_token"
	if tok == "" {
		tok, hint = t.Access, "access_token"
	}
	st, h, err := c.postForm(ctx, c.endpoint("revoke"), url.Values{"token": {tok}, "token_type_hint": {hint}}, nil)
	switch {
	case err != nil:
		return err
	case st == http.StatusTooManyRequests:
		return limite(h)
	case st >= 500:
		return fmt.Errorf("%w: revoke HTTP %d", provedor.ErrTransitorio, st)
	case st == http.StatusOK, st == http.StatusBadRequest: // 400 = token já inválido
		return nil
	}
	return fmt.Errorf("%w: revoke HTTP %d", provedor.ErrResposta, st)
}

func (c *Cumbuca) postForm(ctx context.Context, u string, form url.Values, out any) (int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", provedor.ErrTransitorio, semURL(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", provedor.ErrTransitorio, err)
	}
	if out != nil && len(body) > 0 {
		_ = json.Unmarshal(body, out) // corpo de erro também é JSON; o status decide
	}
	return resp.StatusCode, resp.Header, nil
}

func limite(h http.Header) error {
	d := 60 * time.Second
	if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s > 0 {
		d = time.Duration(s) * time.Second
	}
	return &provedor.LimiteErr{RetryAfter: d}
}

// semURL tira a URL (com query) da mensagem de erro de rede: o code OAuth não vai para o log.
func semURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// Registro é o resultado do registro dinâmico de cliente (RFC 7591).
type Registro struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// Registrar cria um cliente OAuth no realm (comando de operador, uma vez por aplicação).
// nome aparece na tela de consentimento da Cumbuca.
func Registrar(ctx context.Context, hc *http.Client, issuer, nome string, redirectURIs []string, scopes string) (Registro, error) {
	corpo, _ := json.Marshal(map[string]any{
		"client_name":                nome,
		"redirect_uris":              redirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      scopes,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(issuer, "/")+"/clients-registrations/openid-connect", bytes.NewReader(corpo))
	if err != nil {
		return Registro{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return Registro{}, err
	}
	defer resp.Body.Close()
	var r Registro
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return r, fmt.Errorf("registro recusado: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, &r); err != nil || r.ClientID == "" {
		return r, fmt.Errorf("resposta de registro inesperada")
	}
	return r, nil
}
