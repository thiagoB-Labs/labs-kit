package pkce

import "testing"

func TestChallengeRFC7636(t *testing.T) {
	// Exemplo do apêndice B da RFC 7636.
	if got := Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %q", got)
	}
	p, err := Novo()
	if err != nil || len(p.Verifier) != 43 || p.Challenge != Challenge(p.Verifier) {
		t.Fatalf("Novo: %+v %v", p, err)
	}
}
