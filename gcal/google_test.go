package gcal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTrocarExigeEscopo(t *testing.T) {
	escopo := "openid email " + EscopoAgendaDoApp
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code_verifier") != "v" || r.Form.Get("client_secret") != "s" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "refresh_token": "r", "expires_in": 60, "scope": escopo})
	}))
	defer srv.Close()
	g := NovoGoogle(ConfigGoogle{ClientID: "c", ClientSecret: "s", TokenURL: srv.URL})
	agora := time.Unix(1000, 0)
	tk, err := g.Trocar(context.Background(), "code", "v", agora)
	if err != nil || tk.Refresh != "r" || !tk.Expira.Equal(agora.Add(time.Minute)) {
		t.Fatalf("Trocar: %+v %v", tk, err)
	}
	g2 := NovoGoogle(ConfigGoogle{ClientID: "c", ClientSecret: "s", TokenURL: srv.URL, ExigeEscopos: []string{"calendar.freebusy"}})
	if _, err := g2.Trocar(context.Background(), "code", "v", agora); !errors.Is(err, ErrEscopo) {
		t.Fatalf("sem freebusy deveria ser ErrEscopo: %v", err)
	}
	if u := g.URLAutorizacao("st", "ch"); !strings.Contains(u, "code_challenge=ch") || !strings.Contains(u, "calendar.app.created") {
		t.Fatalf("url: %s", u)
	}
}

func TestEventoDiaInteiroEProps(t *testing.T) {
	var corpo map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &corpo)
		_, _ = w.Write([]byte(`{"id":"ev1"}`))
	}))
	defer srv.Close()
	g := NovoGoogle(ConfigGoogle{APIBase: srv.URL})
	ini := time.Date(2026, 11, 20, 2, 0, 0, 0, time.UTC) // 19/11 23h em São Paulo
	id, err := g.InserirEvento(context.Background(), "tok", "cal", Evento{Titulo: "Conta de luz", Inicio: ini, Fim: ini.Add(24 * time.Hour),
		Fuso: "America/Sao_Paulo", DiaInteiro: true, Props: map[string]string{"app": "casa"}, Lembretes: []int{60}})
	if err != nil || id != "ev1" {
		t.Fatalf("InserirEvento: %q %v", id, err)
	}
	if corpo["start"].(map[string]any)["date"] != "2026-11-19" {
		t.Fatalf("dia inteiro usa a data no fuso da agenda: %v", corpo["start"])
	}
	if corpo["extendedProperties"].(map[string]any)["private"].(map[string]any)["app"] != "casa" {
		t.Fatalf("props: %v", corpo["extendedProperties"])
	}
	if corpo["reminders"].(map[string]any)["useDefault"] != false {
		t.Fatalf("lembretes: %v", corpo["reminders"])
	}
	if err := g.ApagarEvento(context.Background(), "ruim", "cal", "ev1"); !errors.Is(err, ErrReautorizar) {
		t.Fatalf("401 deveria ser ErrReautorizar: %v", err)
	}
}
