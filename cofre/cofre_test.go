package cofre

import (
	"bytes"
	"strings"
	"testing"
)

func chave(id, b string) Chave { return Chave{ID: id, Key: []byte(strings.Repeat(b, 32))} }

var pepper = []byte(strings.Repeat("p", 32))

func TestCifraEDecifra(t *testing.T) {
	c, err := New([]Chave{chave("k1", "a")}, pepper)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("conexao-1")
	b1, _ := c.Cifra([]byte("segredo"), aad)
	b2, _ := c.Cifra([]byte("segredo"), aad)
	if bytes.Equal(b1, b2) {
		t.Fatal("nonce repetido: dois blobs iguais")
	}
	if bytes.Contains(b1, []byte("segredo")) {
		t.Fatal("texto claro no blob")
	}
	got, err := c.Decifra(b1, aad)
	if err != nil || string(got) != "segredo" {
		t.Fatalf("decifra: %q %v", got, err)
	}
	// F2.4: blob de uma conexão não abre em outra.
	if _, err := c.Decifra(b1, []byte("conexao-2")); err != ErrCifra {
		t.Fatalf("AAD diferente deveria falhar, veio %v", err)
	}
	adulterado := append([]byte(nil), b1...)
	adulterado[len(adulterado)-1] ^= 1
	if _, err := c.Decifra(adulterado, aad); err != ErrCifra {
		t.Fatal("adulteração não detectada")
	}
	for _, lixo := range [][]byte{nil, {1}, {1, 200}, {9, 2, 'k', '1'}} {
		if _, err := c.Decifra(lixo, aad); err != ErrCifra {
			t.Fatalf("lixo %v deveria falhar", lixo)
		}
	}
}

func TestRotacao(t *testing.T) {
	velho, _ := New([]Chave{chave("k1", "a")}, pepper)
	blob, _ := velho.Cifra([]byte("x"), nil)
	novo, _ := New([]Chave{chave("k2", "b"), chave("k1", "a")}, pepper)
	if got, err := novo.Decifra(blob, nil); err != nil || string(got) != "x" {
		t.Fatalf("chave antiga deveria decifrar: %v", err)
	}
	if !novo.Precisa(blob) {
		t.Fatal("blob da chave antiga deveria pedir recifra")
	}
	b2, _ := novo.Cifra([]byte("x"), nil)
	if novo.Precisa(b2) {
		t.Fatal("blob novo não precisa recifrar")
	}
	if _, err := velho.Decifra(b2, nil); err != ErrCifra {
		t.Fatal("chave desconhecida deveria falhar")
	}
}

func TestHMACNormalizado(t *testing.T) {
	c, _ := New([]Chave{chave("k1", "a")}, pepper)
	if !bytes.Equal(c.HMAC(Documento, "123.456.789-00"), c.HMAC(Documento, "12345678900")) {
		t.Fatal("CPF com e sem pontuação deveriam ter o mesmo HMAC")
	}
	if !bytes.Equal(c.HMAC(ChavePix, "+55 (11) 99999-8888"), c.HMAC(ChavePix, "5511999998888")) {
		t.Fatal("telefone com e sem pontuação")
	}
	if !bytes.Equal(c.HMAC(ChavePix, " Ana@Exemplo.com "), c.HMAC(ChavePix, "ana@exemplo.com")) {
		t.Fatal("e-mail deveria ignorar caixa e espaços")
	}
	if bytes.Equal(c.HMAC(Documento, "12345678900"), c.HMAC(ChavePix, "12345678900")) {
		t.Fatal("tipos diferentes precisam de domínios diferentes")
	}
	if c.HMAC(Documento, " .- ") != nil {
		t.Fatal("valor vazio após normalizar deveria dar nil")
	}
	outro, _ := New([]Chave{chave("k1", "a")}, []byte(strings.Repeat("q", 32)))
	if bytes.Equal(c.HMAC(Documento, "1"), outro.HMAC(Documento, "1")) {
		t.Fatal("pepper diferente deveria mudar o HMAC")
	}
}

func TestNewValida(t *testing.T) {
	if _, err := New(nil, pepper); err == nil {
		t.Fatal("sem chaves")
	}
	if _, err := New([]Chave{chave("k1", "a")}, []byte("curto")); err == nil {
		t.Fatal("pepper curto")
	}
	if _, err := New([]Chave{{ID: "k", Key: []byte("curta")}}, pepper); err == nil {
		t.Fatal("chave curta")
	}
}

func TestParseChaves(t *testing.T) {
	ks, err := ParseChaves("k2:" + strings.Repeat("A", 43) + "=,k1:" + strings.Repeat("B", 43) + "=")
	if err != nil || len(ks) != 2 || ks[0].ID != "k2" || len(ks[1].Key) != 32 {
		t.Fatalf("ParseChaves: %v %v", ks, err)
	}
	for _, ruim := range []string{"", "k1", "k1:abc", ":" + strings.Repeat("A", 43) + "="} {
		if _, err := ParseChaves(ruim); err == nil {
			t.Errorf("ParseChaves(%q) deveria falhar", ruim)
		}
	}
}
