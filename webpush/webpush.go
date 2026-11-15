// Package webpush envia Web Push com VAPID (RFC 8292) e mensagem cifrada (RFC 8291) para os
// serviços de push dos navegadores. Extraído do psidalidi-bem-estar (B13, B16) e generalizado:
// o conteúdo é do chamador, que decide o que pode aparecer numa notificação.
package webpush

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	wp "github.com/SherClockHolmes/webpush-go"
)

// Assinatura é a PushSubscription de um navegador (endpoint + chaves).
type Assinatura struct {
	Endpoint string `json:"endpoint"`
	P256dh   string `json:"p256dh"`
	Auth     string `json:"auth"`
}

// Urgência (RFC 8030 §5.3).
type Urgencia string

// Urgências aceitas.
const (
	UrgenciaBaixa  Urgencia = "low"
	UrgenciaNormal Urgencia = "normal"
	UrgenciaAlta   Urgencia = "high"
)

// Opcoes de um envio.
type Opcoes struct {
	// TTL: por quanto tempo o serviço de push guarda a mensagem se o aparelho estiver offline.
	TTL time.Duration
	// Topic substitui uma mensagem ainda não entregue com o mesmo tópico (até 32 caracteres base64url).
	Topic    string
	Urgencia Urgencia
}

// Cliente envia com uma chave VAPID.
type Cliente struct {
	privada, publica, assunto string
	HTTP                      *http.Client
}

// ErrDesligado é devolvido por New quando não há chave: o chamador decide se isso é aceitável.
var ErrDesligado = errors.New("webpush: sem chave VAPID")

// New valida a chave privada VAPID (32 bytes em base64url) e o assunto (mailto: ou https://) e
// deriva a chave pública.
func New(privada, assunto string) (*Cliente, error) {
	if strings.TrimSpace(privada) == "" {
		return nil, ErrDesligado
	}
	d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(privada), "="))
	if err != nil || len(d) != 32 {
		return nil, errors.New("webpush: a chave privada VAPID deve ter 32 bytes em base64url")
	}
	k, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf("webpush: chave privada VAPID inválida: %w", err)
	}
	assunto = strings.TrimPrefix(strings.TrimSpace(assunto), "mailto:")
	if assunto == "" || (!strings.HasPrefix(assunto, "https://") && !strings.Contains(assunto, "@")) {
		return nil, errors.New("webpush: o assunto VAPID deve ser um e-mail ou uma URL https")
	}
	return &Cliente{privada: base64.RawURLEncoding.EncodeToString(d),
		publica: base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), assunto: assunto}, nil
}

// GeraChavePrivada cria uma chave VAPID nova (32 bytes em base64url).
func GeraChavePrivada() (string, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), nil
}

// ChavePublica é o applicationServerKey que o navegador usa em pushManager.subscribe.
func (c *Cliente) ChavePublica() string { return c.publica }

// Serviços de push dos navegadores. O servidor só faz POST para eles: um endpoint qualquer viraria
// um jeito de fazer o serviço chamar endereços arbitrários (SSRF).
var hostsDePush = []string{
	"fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com",
	".push.apple.com", ".notify.windows.com", ".push.services.mozilla.com",
}

// EndpointValido diz se o endpoint é https de um serviço de push conhecido.
func EndpointValido(endpoint string) bool {
	if len(endpoint) > 1000 {
		return false
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, ok := range hostsDePush {
		if h == ok || (strings.HasPrefix(ok, ".") && strings.HasSuffix(h, ok)) {
			return true
		}
	}
	return false
}

// Valida confere endpoint e chaves de uma assinatura antes de guardá-la.
func (a Assinatura) Valida() error {
	if !EndpointValido(a.Endpoint) {
		return errors.New("webpush: endpoint não é de um serviço de push conhecido")
	}
	p, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(a.P256dh, "="))
	if err != nil || len(p) != 65 {
		return errors.New("webpush: p256dh inválida")
	}
	s, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(a.Auth, "="))
	if err != nil || len(s) != 16 {
		return errors.New("webpush: auth inválida")
	}
	return nil
}

// Resultado de um envio em lote.
type Resultado struct {
	// Invalidos são os endpoints que o serviço diz que não existem mais (404/410) ou que não
	// passam em EndpointValido: apague-os.
	Invalidos []string
	Enviados  int
	Falhas    int
}

// Envia o payload (já serializado, até ~3 KB) a cada assinatura. Erro só se houve falha que vale
// retentar (rede, 5xx, 429); assinaturas mortas vêm em Resultado.Invalidos.
func (c *Cliente) Envia(ctx context.Context, as []Assinatura, payload []byte, o Opcoes) (Resultado, error) {
	cli := c.HTTP
	if cli == nil {
		cli = &http.Client{Timeout: 15 * time.Second}
	}
	ttl := int(o.TTL / time.Second)
	if ttl <= 0 {
		ttl = 3600
	}
	urg := wp.Urgency(o.Urgencia)
	if urg == "" {
		urg = wp.UrgencyNormal
	}
	var r Resultado
	for _, a := range as {
		if !EndpointValido(a.Endpoint) {
			r.Invalidos = append(r.Invalidos, a.Endpoint)
			continue
		}
		resp, err := wp.SendNotificationWithContext(ctx, payload,
			&wp.Subscription{Endpoint: a.Endpoint, Keys: wp.Keys{P256dh: a.P256dh, Auth: a.Auth}},
			&wp.Options{HTTPClient: cli, Subscriber: c.assunto, VAPIDPublicKey: c.publica, VAPIDPrivateKey: c.privada,
				TTL: ttl, Urgency: urg, Topic: o.Topic})
		if err != nil {
			r.Falhas++
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
			r.Invalidos = append(r.Invalidos, a.Endpoint)
		case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden:
			// Assinatura feita com outra chave VAPID ou corrompida: não adianta retentar.
			r.Invalidos = append(r.Invalidos, a.Endpoint)
		case resp.StatusCode >= 300:
			r.Falhas++
		default:
			r.Enviados++
		}
	}
	if r.Falhas > 0 {
		return r, fmt.Errorf("webpush: %d de %d envios falharam", r.Falhas, len(as))
	}
	return r, nil
}
