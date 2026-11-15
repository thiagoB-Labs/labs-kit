// Package telefone normaliza números de WhatsApp em E.164 sem "+" e lida com o 9º dígito dos
// celulares brasileiros (o WhatsApp vincula muitos celulares sem o 9, e quem digita o próprio
// número costuma pô-lo). Extraído do psidalidi-api (R1.1, R9.2).
package telefone

import (
	"regexp"
	"strings"
	"unicode"
)

var e164 = regexp.MustCompile(`^[1-9][0-9]{9,14}$`)

// Valido diz se s é E.164 sem "+".
func Valido(s string) bool { return e164.MatchString(s) }

// Normaliza tira tudo que não é dígito e, se sobrarem 10 ou 11 dígitos (DDD + número) sem "+" na
// frente, assume Brasil (55). Devolve "" se o resultado não for E.164.
func Normaliza(s string) string {
	internacional := strings.HasPrefix(strings.TrimSpace(s), "+")
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	n := strings.TrimLeft(b.String(), "0")
	if !internacional && (len(n) == 10 || len(n) == 11) {
		n = "55" + n
	}
	if !Valido(n) {
		return ""
	}
	return n
}

// Variantes devolve o número e, se for celular brasileiro, a variante com/sem o 9º dígito:
// 55 + DDD + 9 + 8 dígitos ⇄ 55 + DDD + 8 dígitos. A primeira é sempre o próprio número.
func Variantes(n string) []string {
	out := []string{n}
	if len(n) < 5 || n[:2] != "55" || n[2] == '0' || n[3] == '0' {
		return out
	}
	switch len(n) {
	case 13: // 55 DD 9 XXXXXXXX
		if n[4] == '9' {
			out = append(out, n[:4]+n[5:])
		}
	case 12: // 55 DD XXXXXXXX
		out = append(out, n[:4]+"9"+n[4:])
	}
	return out
}

// Canonico devolve a forma com o 9º dígito para celulares brasileiros (12 → 13 dígitos quando o
// número começa com 6–9, faixa dos celulares), para que o mesmo telefone tenha uma chave só.
func Canonico(n string) string {
	if len(n) == 12 && n[:2] == "55" && n[4] >= '6' {
		return n[:4] + "9" + n[4:]
	}
	return n
}

// Mascara esconde o meio do número para exibir ("+55 44 •••• 8888").
func Mascara(n string) string {
	if len(n) < 8 {
		return "••••"
	}
	return "+" + n[:2] + " " + n[2:4] + " •••• " + n[len(n)-4:]
}
