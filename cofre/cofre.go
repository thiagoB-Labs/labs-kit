// Package cofre cifra segredos guardados no banco (tokens OAuth de terceiros, chaves) com
// AES-256-GCM e rotação de chave, e calcula HMACs de identificadores normalizados. Nada daqui é
// logado. Extraído do psidalidi-fin (F2.4, F6.2).
package cofre

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const versao byte = 1

// ErrCifra indica blob adulterado, de outra linha (AAD) ou com chave desconhecida.
var ErrCifra = errors.New("cofre: não foi possível decifrar")

// Chave é uma chave AES-256 com o id gravado em cada blob (rotação).
type Chave struct {
	ID  string
	Key []byte
}

// ParseChaves lê "id:base64(32 bytes)[,id:base64...]": a primeira cifra, todas decifram.
func ParseChaves(s string) ([]Chave, error) {
	var out []Chave
	for _, parte := range strings.Split(strings.TrimSpace(s), ",") {
		id, b64, ok := strings.Cut(strings.TrimSpace(parte), ":")
		if !ok || id == "" || len(id) > 16 {
			return nil, errors.New("cofre: chave deve ser id:base64(32 bytes)")
		}
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("cofre: chave %q não tem 32 bytes em base64", id)
		}
		out = append(out, Chave{ID: id, Key: k})
	}
	if len(out) == 0 {
		return nil, errors.New("cofre: sem chaves")
	}
	return out, nil
}

// Cofre guarda as chaves. A primeira cifra; todas decifram (rotação).
type Cofre struct {
	keys   []Chave
	aeads  map[string]cipher.AEAD
	pepper []byte
}

// New valida as chaves e o pepper.
func New(keys []Chave, pepper []byte) (*Cofre, error) {
	if len(keys) == 0 {
		return nil, errors.New("cofre: sem chaves")
	}
	if len(pepper) < 32 {
		return nil, errors.New("cofre: pepper curto")
	}
	c := &Cofre{keys: keys, aeads: map[string]cipher.AEAD{}, pepper: pepper}
	for _, k := range keys {
		if len(k.ID) == 0 || len(k.ID) > 16 || len(k.Key) != 32 {
			return nil, fmt.Errorf("cofre: chave %q inválida", k.ID)
		}
		b, err := aes.NewCipher(k.Key)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(b)
		if err != nil {
			return nil, err
		}
		c.aeads[k.ID] = g
	}
	return c, nil
}

// Cifra devolve versão | len(id) | id | nonce | ciphertext. aad amarra o blob à linha
// (ex.: id da conexão), para que não possa ser copiado para outra.
func (c *Cofre) Cifra(plain, aad []byte) ([]byte, error) {
	k := c.keys[0]
	g := c.aeads[k.ID]
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(k.ID)+len(nonce)+len(plain)+g.Overhead())
	out = append(out, versao, byte(len(k.ID)))
	out = append(out, k.ID...)
	out = append(out, nonce...)
	return g.Seal(out, nonce, plain, aad), nil
}

// Decifra é o inverso de Cifra.
func (c *Cofre) Decifra(blob, aad []byte) ([]byte, error) {
	if len(blob) < 2 || blob[0] != versao {
		return nil, ErrCifra
	}
	n := int(blob[1])
	if len(blob) < 2+n {
		return nil, ErrCifra
	}
	g, ok := c.aeads[string(blob[2:2+n])]
	if !ok {
		return nil, ErrCifra
	}
	rest := blob[2+n:]
	if len(rest) < g.NonceSize()+g.Overhead() {
		return nil, ErrCifra
	}
	plain, err := g.Open(nil, rest[:g.NonceSize()], rest[g.NonceSize():], aad)
	if err != nil {
		return nil, ErrCifra
	}
	return plain, nil
}

// Precisa diz se o blob foi cifrado com uma chave que não é a atual (para recifrar).
func (c *Cofre) Precisa(blob []byte) bool {
	return len(blob) < 2 || int(blob[1]) > len(blob)-2 || string(blob[2:2+int(blob[1])]) != c.keys[0].ID
}

// Tipos de identificador (domínios separados de HMAC).
const (
	Documento = "doc"
	ChavePix  = "pix"
	Conta     = "conta"
	ContaProv = "conta_provedor"
)

// HMAC devolve o HMAC-SHA256 do valor normalizado, ou nil se o valor normalizado for vazio.
func (c *Cofre) HMAC(tipo, valor string) []byte {
	v := Normaliza(tipo, valor)
	if v == "" {
		return nil
	}
	m := hmac.New(sha256.New, c.pepper)
	m.Write([]byte(tipo))
	m.Write([]byte{0})
	m.Write([]byte(v))
	return m.Sum(nil)
}

// Normaliza deixa o identificador numa forma canônica: documento e conta só com dígitos;
// chave PIX sem espaços, minúscula e, se for só dígitos com pontuação (CPF/telefone), só dígitos.
func Normaliza(tipo, valor string) string {
	valor = strings.TrimSpace(valor)
	switch tipo {
	case Documento, Conta:
		return digitos(valor)
	case ChavePix:
		v := strings.ToLower(strings.Join(strings.Fields(valor), ""))
		if strings.ContainsRune(v, '@') {
			return v // e-mail
		}
		// CPF, CNPJ e telefone chegam com pontuação variável: só os dígitos identificam.
		if strings.Trim(v, "0123456789.-/()+") == "" {
			return digitos(v)
		}
		return v // chave aleatória
	default:
		return valor
	}
}

func digitos(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
