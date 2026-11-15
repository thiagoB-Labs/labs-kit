// Package pkce gera o par verifier/challenge do PKCE S256 (RFC 7636) e states de uso único para
// fluxos OAuth de navegador.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Par é o verifier (guardado no servidor) e o challenge (vai na URL de autorização).
type Par struct {
	Verifier  string
	Challenge string
}

// Novo gera um verifier de 43 caracteres (32 bytes aleatórios) e o challenge S256.
func Novo() (Par, error) {
	v, err := Aleatorio(32)
	if err != nil {
		return Par{}, err
	}
	return Par{Verifier: v, Challenge: Challenge(v)}, nil
}

// Challenge é BASE64URL(SHA256(verifier)).
func Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Aleatorio devolve n bytes aleatórios em base64url sem padding (para states e tokens).
func Aleatorio(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
