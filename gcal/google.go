// Package gcal é um cliente mínimo do Google Agenda para apps que mantêm uma agenda própria na
// conta da pessoa: OAuth com PKCE S256 e refresh token, agenda secundária criada pelo app
// (escopo calendar.app.created), eventos com dono identificado em extendedProperties e
// livre/ocupado da agenda principal. Extraído do psidalidi-api (G1–G8) e generalizado.
package gcal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	_ "time/tzdata" // fusos embutidos: o horário do evento depende do fuso da agenda
)

// Escopos.
const (
	EscopoAgendaDoApp = "https://www.googleapis.com/auth/calendar.app.created"
	EscopoOcupado     = "https://www.googleapis.com/auth/calendar.freebusy"
	// Escopos é o conjunto padrão: e-mail da conta, agenda do app e livre/ocupado das demais.
	Escopos = "openid email " + EscopoAgendaDoApp + " " + EscopoOcupado
)

// Erros classificados.
var (
	// ErrReautorizar: refresh recusado, token revogado ou escopo retirado. Sem retentativa.
	ErrReautorizar = errors.New("gcal: acesso ao Google recusado")
	// ErrNaoEncontrado: evento ou agenda não existe mais (404/410).
	ErrNaoEncontrado = errors.New("gcal: não encontrado no Google")
	// ErrTransitorio: rede, 5xx, 429 ou limite de taxa. Retentativa com backoff.
	ErrTransitorio = errors.New("gcal: falha transitória do Google")
	// ErrGoogle: outra recusa do Google (4xx). Retentativa espaçada; vira métrica.
	ErrGoogle = errors.New("gcal: o Google recusou o pedido")
)

// Tokens OAuth. Nunca aparecem em log.
type Tokens struct {
	Access  string    `json:"a"`
	Refresh string    `json:"r"`
	Expira  time.Time `json:"e"`
}

// String esconde os segredos.
func (Tokens) String() string { return "gcal.Tokens{…}" }

// GoString esconde os segredos (%#v).
func (t Tokens) GoString() string { return t.String() }

// Evento que o app mantém no Google. Props vai em extendedProperties.private (o app reconhece os
// próprios eventos por ali). DiaInteiro usa só a data de Inicio e Fim (Fim exclusivo).
type Evento struct {
	Titulo     string
	Descricao  string
	Inicio     time.Time
	Fim        time.Time
	Fuso       string
	DiaInteiro bool
	Props      map[string]string
	// Lembretes em minutos antes; vazio = os padrões da agenda.
	Lembretes []int
}

// Intervalo ocupado.
type Intervalo struct {
	Inicio time.Time `json:"inicio"`
	Fim    time.Time `json:"fim"`
}

// ConfigGoogle do cliente. URLs vazias = as do Google (os testes apontam para um servidor falso).
type ConfigGoogle struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthURL      string
	TokenURL     string
	RevokeURL    string
	UserinfoURL  string
	APIBase      string
	// Escopos pedidos; vazio = Escopos. ExigeEscopos são conferidos no retorno do código.
	Escopos      string
	ExigeEscopos []string
	HTTP         *http.Client
}

// Google é o cliente mínimo das APIs usadas.
type Google struct{ c ConfigGoogle }

// NovoGoogle preenche os padrões.
func NovoGoogle(c ConfigGoogle) *Google {
	padrao := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	padrao(&c.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
	padrao(&c.TokenURL, "https://oauth2.googleapis.com/token")
	padrao(&c.RevokeURL, "https://oauth2.googleapis.com/revoke")
	padrao(&c.UserinfoURL, "https://openidconnect.googleapis.com/v1/userinfo")
	padrao(&c.APIBase, "https://www.googleapis.com/calendar/v3")
	padrao(&c.Escopos, Escopos)
	if c.ExigeEscopos == nil {
		c.ExigeEscopos = []string{"calendar.app.created"}
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	return &Google{c: c}
}

// URLAutorizacao monta o pedido OAuth com PKCE S256 e refresh token garantido.
func (g *Google) URLAutorizacao(state, challenge string) string {
	q := url.Values{
		"response_type":          {"code"},
		"client_id":              {g.c.ClientID},
		"redirect_uri":           {g.c.RedirectURI},
		"scope":                  {g.c.Escopos},
		"state":                  {state},
		"code_challenge":         {challenge},
		"code_challenge_method":  {"S256"},
		"access_type":            {"offline"},
		"prompt":                 {"consent"},
		"include_granted_scopes": {"false"},
	}
	return g.c.AuthURL + "?" + q.Encode()
}

type respostaToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Erro         string `json:"error"`
}

func (g *Google) token(ctx context.Context, form url.Values) (respostaToken, error) {
	form.Set("client_id", g.c.ClientID)
	form.Set("client_secret", g.c.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return respostaToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.c.HTTP.Do(req)
	if err != nil {
		return respostaToken{}, fmt.Errorf("%w: %v", ErrTransitorio, err)
	}
	defer resp.Body.Close()
	var r respostaToken
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r)
	switch {
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return r, fmt.Errorf("%w: token %d", ErrTransitorio, resp.StatusCode)
	case r.Erro == "invalid_grant" || resp.StatusCode == http.StatusUnauthorized:
		return r, fmt.Errorf("%w: %s", ErrReautorizar, r.Erro)
	case resp.StatusCode != http.StatusOK || r.AccessToken == "":
		return r, fmt.Errorf("%w: token %d %s", ErrGoogle, resp.StatusCode, r.Erro)
	}
	return r, nil
}

// Trocar troca o código pelo par de tokens. Exige refresh token e os escopos de ExigeEscopos.
func (g *Google) Trocar(ctx context.Context, code, verifier string, agora time.Time) (Tokens, error) {
	r, err := g.token(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {verifier}, "redirect_uri": {g.c.RedirectURI}})
	if err != nil {
		return Tokens{}, err
	}
	if r.RefreshToken == "" {
		return Tokens{}, fmt.Errorf("%w: sem refresh token", ErrGoogle)
	}
	for _, s := range g.c.ExigeEscopos {
		if r.Scope != "" && !strings.Contains(r.Scope, s) {
			return Tokens{}, fmt.Errorf("%w: escopo %s não concedido", ErrEscopo, s)
		}
	}
	return Tokens{Access: r.AccessToken, Refresh: r.RefreshToken, Expira: expira(agora, r.ExpiresIn)}, nil
}

// ErrEscopo: a pessoa desmarcou uma das permissões na tela do Google.
var ErrEscopo = errors.New("gcal: permissão não concedida")

// Renovar usa o refresh token. O Google normalmente não devolve outro: mantém o atual.
func (g *Google) Renovar(ctx context.Context, t Tokens, agora time.Time) (Tokens, error) {
	r, err := g.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t.Refresh}})
	if err != nil {
		return t, err
	}
	n := Tokens{Access: r.AccessToken, Refresh: t.Refresh, Expira: expira(agora, r.ExpiresIn)}
	if r.RefreshToken != "" {
		n.Refresh = r.RefreshToken
	}
	return n, nil
}

func expira(agora time.Time, s int) time.Time {
	if s <= 0 {
		s = 3600
	}
	return agora.Add(time.Duration(s) * time.Second)
}

// Revogar invalida o token no Google (o refresh revoga o acesso todo).
func (g *Google) Revogar(ctx context.Context, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.c.RevokeURL,
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransitorio, err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest { // 400 = já revogado
		return nil
	}
	return fmt.Errorf("%w: revoke %d", ErrTransitorio, resp.StatusCode)
}

// chamada faz um pedido autenticado e decodifica a resposta em out (se não for nil).
func (g *Google) chamada(ctx context.Context, access, metodo, endereco string, corpo, out any) error {
	var body io.Reader
	if corpo != nil {
		b, err := json.Marshal(corpo)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, metodo, endereco, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	if corpo != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransitorio, err)
	}
	defer resp.Body.Close()
	dados, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(dados) > 0 {
			if err := json.Unmarshal(dados, out); err != nil {
				return fmt.Errorf("%w: resposta ilegível", ErrGoogle)
			}
		}
		return nil
	}
	return classifica(resp.StatusCode, dados)
}

// classifica um erro da Calendar API (G7). 403 com motivo de taxa é transitório.
func classifica(status int, corpo []byte) error {
	var e struct {
		Error struct {
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
			Status string `json:"status"`
		} `json:"error"`
	}
	_ = json.Unmarshal(corpo, &e)
	motivo := e.Error.Status
	if len(e.Error.Errors) > 0 {
		motivo = e.Error.Errors[0].Reason
	}
	switch {
	case status == http.StatusUnauthorized:
		return fmt.Errorf("%w: %d", ErrReautorizar, status)
	case status == http.StatusNotFound || status == http.StatusGone:
		return fmt.Errorf("%w: %d", ErrNaoEncontrado, status)
	case status == http.StatusTooManyRequests || status >= 500,
		status == http.StatusForbidden && strings.Contains(strings.ToLower(motivo), "ratelimit"):
		return fmt.Errorf("%w: %d %s", ErrTransitorio, status, motivo)
	case status == http.StatusForbidden && (motivo == "insufficientPermissions" || motivo == "PERMISSION_DENIED"):
		return fmt.Errorf("%w: %d %s", ErrReautorizar, status, motivo)
	}
	return fmt.Errorf("%w: %d %s", ErrGoogle, status, motivo)
}

// Email da conta conectada (openid email).
func (g *Google) Email(ctx context.Context, access string) (string, error) {
	var r struct {
		Email string `json:"email"`
	}
	if err := g.chamada(ctx, access, http.MethodGet, g.c.UserinfoURL, nil, &r); err != nil {
		return "", err
	}
	if r.Email == "" {
		return "", fmt.Errorf("%w: sem e-mail", ErrGoogle)
	}
	return r.Email, nil
}

// CriarAgenda cria a agenda secundária do app.
func (g *Google) CriarAgenda(ctx context.Context, access, nome, descricao, fuso string) (string, error) {
	var r struct {
		ID string `json:"id"`
	}
	err := g.chamada(ctx, access, http.MethodPost, g.c.APIBase+"/calendars",
		map[string]string{"summary": nome, "description": descricao, "timeZone": fuso}, &r)
	if err == nil && r.ID == "" {
		err = fmt.Errorf("%w: agenda sem id", ErrGoogle)
	}
	return r.ID, err
}

// AgendaExiste confere se a agenda guardada ainda existe.
func (g *Google) AgendaExiste(ctx context.Context, access, id string) (bool, error) {
	err := g.chamada(ctx, access, http.MethodGet, g.c.APIBase+"/calendars/"+url.PathEscape(id), nil, nil)
	if errors.Is(err, ErrNaoEncontrado) {
		return false, nil
	}
	return err == nil, err
}

// ApagarAgenda remove a agenda do app. Já apagada conta como sucesso.
func (g *Google) ApagarAgenda(ctx context.Context, access, id string) error {
	err := g.chamada(ctx, access, http.MethodDelete, g.c.APIBase+"/calendars/"+url.PathEscape(id), nil, nil)
	if errors.Is(err, ErrNaoEncontrado) {
		return nil
	}
	return err
}

func corpoEvento(e Evento) map[string]any {
	// O horário vai no fuso da agenda, não no do processo: o servidor pode rodar em UTC.
	loc := time.UTC
	if l, err := time.LoadLocation(e.Fuso); err == nil {
		loc = l
	}
	quando := func(t time.Time) map[string]string {
		if e.DiaInteiro {
			return map[string]string{"date": t.In(loc).Format(time.DateOnly)}
		}
		return map[string]string{"dateTime": t.In(loc).Format(time.RFC3339), "timeZone": e.Fuso}
	}
	lembretes := map[string]any{"useDefault": true}
	if len(e.Lembretes) > 0 {
		var ov []map[string]any
		for _, m := range e.Lembretes {
			ov = append(ov, map[string]any{"method": "popup", "minutes": m})
		}
		lembretes = map[string]any{"useDefault": false, "overrides": ov}
	}
	props := map[string]string{}
	for k, v := range e.Props {
		props[k] = v
	}
	return map[string]any{
		"summary":            e.Titulo,
		"description":        e.Descricao,
		"start":              quando(e.Inicio),
		"end":                quando(e.Fim),
		"visibility":         "private", // em agenda compartilhada, os outros veem só "ocupado"
		"reminders":          lembretes,
		"extendedProperties": map[string]any{"private": props},
		// Nunca há convidados: o Google mandaria e-mail a terceiros.
		"attendees":               []any{},
		"guestsCanInviteOthers":   false,
		"guestsCanSeeOtherGuests": false,
	}
}

func (g *Google) urlEventos(agenda string) string {
	return g.c.APIBase + "/calendars/" + url.PathEscape(agenda) + "/events"
}

// InserirEvento cria o evento e devolve o id.
func (g *Google) InserirEvento(ctx context.Context, access, agenda string, e Evento) (string, error) {
	var r struct {
		ID string `json:"id"`
	}
	err := g.chamada(ctx, access, http.MethodPost, g.urlEventos(agenda)+"?sendUpdates=none", corpoEvento(e), &r)
	if err == nil && r.ID == "" {
		err = fmt.Errorf("%w: evento sem id", ErrGoogle)
	}
	return r.ID, err
}

// AtualizarEvento substitui o evento inteiro (PUT): mudanças feitas no Google são sobrescritas.
func (g *Google) AtualizarEvento(ctx context.Context, access, agenda, id string, e Evento) error {
	return g.chamada(ctx, access, http.MethodPut, g.urlEventos(agenda)+"/"+url.PathEscape(id)+"?sendUpdates=none",
		corpoEvento(e), nil)
}

// ApagarEvento remove o evento. Já apagado conta como sucesso.
func (g *Google) ApagarEvento(ctx context.Context, access, agenda, id string) error {
	err := g.chamada(ctx, access, http.MethodDelete, g.urlEventos(agenda)+"/"+url.PathEscape(id)+"?sendUpdates=none", nil, nil)
	if errors.Is(err, ErrNaoEncontrado) {
		return nil
	}
	return err
}

// Ocupado consulta freebusy.query na agenda principal. Só intervalos, sem título.
func (g *Google) Ocupado(ctx context.Context, access string, de, ate time.Time) ([]Intervalo, error) {
	var r struct {
		Calendars map[string]struct {
			Busy []struct {
				Start time.Time `json:"start"`
				End   time.Time `json:"end"`
			} `json:"busy"`
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"calendars"`
	}
	err := g.chamada(ctx, access, http.MethodPost, g.c.APIBase+"/freeBusy", map[string]any{
		"timeMin": de.UTC().Format(time.RFC3339), "timeMax": ate.UTC().Format(time.RFC3339),
		"items": []map[string]string{{"id": "primary"}},
	}, &r)
	if err != nil {
		return nil, err
	}
	var out []Intervalo
	for _, c := range r.Calendars {
		if len(c.Errors) > 0 {
			return nil, fmt.Errorf("%w: freebusy %s", ErrGoogle, c.Errors[0].Reason)
		}
		for _, b := range c.Busy {
			out = append(out, Intervalo{Inicio: b.Start, Fim: b.End})
		}
	}
	return out, nil
}
