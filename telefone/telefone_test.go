package telefone

import (
	"slices"
	"testing"
)

func TestNormaliza(t *testing.T) {
	for in, want := range map[string]string{
		"(44) 99999-8888":   "5544999998888",
		"+55 44 99999-8888": "5544999998888",
		"044 9999-8888":     "554499998888",
		"5544999998888":     "5544999998888",
		"123":               "",
		"+1 415 555 2671":   "14155552671",
		"0000":              "",
	} {
		if got := Normaliza(in); got != want {
			t.Errorf("Normaliza(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestVariantesECanonico(t *testing.T) {
	if v := Variantes("5544999998888"); !slices.Equal(v, []string{"5544999998888", "554499998888"}) {
		t.Fatalf("variantes 13: %v", v)
	}
	if v := Variantes("554499998888"); !slices.Equal(v, []string{"554499998888", "5544999998888"}) {
		t.Fatalf("variantes 12: %v", v)
	}
	if v := Variantes("14155552671"); len(v) != 1 {
		t.Fatalf("fora do Brasil: %v", v)
	}
	if c := Canonico("554499998888"); c != "5544999998888" {
		t.Fatalf("canônico: %s", c)
	}
	if c := Canonico("554432228888"); c != "554432228888" {
		t.Fatalf("fixo não ganha 9: %s", c)
	}
	if m := Mascara("5544999998888"); m != "+55 44 •••• 8888" {
		t.Fatalf("máscara: %s", m)
	}
}
