package webpush

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"sync"
	"testing"
)

type transporteFalso struct {
	mu     sync.Mutex
	urls   []string
	status map[string]int
	corpo  map[string]string
}

func (f *transporteFalso) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, _ = io.ReadAll(r.Body)
	f.urls = append(f.urls, r.URL.String())
	st := f.status[r.URL.String()]
	if st == 0 {
		st = http.StatusCreated
	}
	return &http.Response{StatusCode: st, Body: io.NopCloser(bytes.NewReader([]byte(f.corpo[r.URL.String()]))), Header: http.Header{}}, nil
}

func assinatura(t *testing.T, endpoint string) Assinatura {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	return Assinatura{Endpoint: endpoint, P256dh: base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()),
		Auth: base64.RawURLEncoding.EncodeToString(auth)}
}

func TestNew(t *testing.T) {
	priv, err := GeraChavePrivada()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(priv, "mailto:ops@example.com")
	if err != nil || len(c.ChavePublica()) != 87 {
		t.Fatalf("New: %v %q", err, c.ChavePublica())
	}
	if _, err := New("", "a@b"); err != ErrDesligado {
		t.Fatalf("sem chave deveria ser ErrDesligado, veio %v", err)
	}
	for _, x := range []struct{ priv, assunto string }{{"curta", "a@b"}, {priv, ""}, {priv, "http://x"}} {
		if _, err := New(x.priv, x.assunto); err == nil {
			t.Fatalf("aceitou %+v", x)
		}
	}
}

func TestEndpointValido(t *testing.T) {
	for e, ok := range map[string]bool{
		"https://fcm.googleapis.com/fcm/send/abc":              true,
		"https://updates.push.services.mozilla.com/wpush/v2/x": true,
		"https://web.push.apple.com/QH8x":                      true,
		"https://wns2-par02p.notify.windows.com/w/?token=x":    true,
		"http://fcm.googleapis.com/fcm/send/abc":               false,
		"https://fcm.googleapis.com.evil.test/x":               false,
		"https://fcm.googleapis.com:8443/x":                    false,
		"https://user@fcm.googleapis.com/x":                    false,
		"https://169.254.169.254/latest":                       false,
	} {
		if EndpointValido(e) != ok {
			t.Errorf("EndpointValido(%q) != %v", e, ok)
		}
	}
}

func TestValida(t *testing.T) {
	a := assinatura(t, "https://fcm.googleapis.com/fcm/send/1")
	if err := a.Valida(); err != nil {
		t.Fatal(err)
	}
	b := a
	b.Auth = "xx"
	if b.Valida() == nil {
		t.Fatal("auth curta aceita")
	}
}

func TestEnvia(t *testing.T) {
	priv, _ := GeraChavePrivada()
	c, _ := New(priv, "https://example.com")
	viva := assinatura(t, "https://fcm.googleapis.com/fcm/send/viva")
	morta := assinatura(t, "https://fcm.googleapis.com/fcm/send/morta")
	falha := assinatura(t, "https://fcm.googleapis.com/fcm/send/falha")
	estranha := assinatura(t, "https://evil.test/x")
	tr := &transporteFalso{status: map[string]int{morta.Endpoint: http.StatusGone, falha.Endpoint: http.StatusBadGateway}}
	c.HTTP = &http.Client{Transport: tr}

	r, err := c.Envia(context.Background(), []Assinatura{viva, morta, estranha}, []byte(`{"t":"oi"}`), Opcoes{})
	if err != nil || r.Enviados != 1 || len(r.Invalidos) != 2 {
		t.Fatalf("Envia: %+v %v", r, err)
	}
	if len(tr.urls) != 2 {
		t.Fatalf("endpoint fora da lista não pode ser chamado: %v", tr.urls)
	}
	if _, err := c.Envia(context.Background(), []Assinatura{falha}, []byte(`{}`), Opcoes{}); err == nil {
		t.Fatal("502 deveria pedir retentativa")
	}
}

// 403 da Apple por token: não é assinatura morta. Apagar faria o push sumir em silêncio.
func TestEnviaRecusaNaoApaga(t *testing.T) {
	priv, _ := GeraChavePrivada()
	c, _ := New(priv, "https://example.com")
	apple := assinatura(t, "https://web.push.apple.com/QGx")
	tr := &transporteFalso{status: map[string]int{apple.Endpoint: http.StatusForbidden},
		corpo: map[string]string{apple.Endpoint: "{\"reason\":\n \"BadJwtToken\"}"}}
	c.HTTP = &http.Client{Transport: tr}
	r, err := c.Envia(context.Background(), []Assinatura{apple}, []byte(`{}`), Opcoes{})
	if err != nil || len(r.Invalidos) != 0 || r.Enviados != 0 {
		t.Fatalf("Envia: %+v %v", r, err)
	}
	if len(r.Rejeitados) != 1 || r.Rejeitados[0] != (Rejeicao{Host: "web.push.apple.com", Status: 403, Motivo: `{"reason": "BadJwtToken"}`}) {
		t.Fatalf("rejeição: %+v", r.Rejeitados)
	}
}
