package cumbuca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	provedor "github.com/thiagoB-Labs/labs-kit/openfinance"
)

// servidor imita o Keycloak e o MCP da Cumbuca com respostas no padrão Open Finance Brasil.
type servidor struct {
	mu        sync.Mutex
	revogados map[string]bool
	sse       bool
	falhaMCP  int // status a devolver no próximo tools/call
	paginas   int
	real      bool             // imita as tools e o formato observados na Cumbuca em 2026-11
	chamadas  []map[string]any // argumentos de cada tools/call (com "_tool")
}

func (s *servidor) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realm/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "cid" || p != "sec" {
			w.WriteHeader(401)
			return
		}
		_ = r.ParseForm()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code_verifier") == "" || r.Form.Get("code") == "usado" {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":"invalid_grant"}`)
				return
			}
			fmt.Fprint(w, `{"access_token":"AT1","refresh_token":"RT1","expires_in":300,"refresh_expires_in":0}`)
		case "refresh_token":
			s.mu.Lock()
			rev := s.revogados[r.Form.Get("refresh_token")]
			s.mu.Unlock()
			if rev {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":"invalid_grant"}`)
				return
			}
			fmt.Fprint(w, `{"access_token":"AT2","expires_in":300}`) // sem refresh novo: mantém o anterior
		}
	})
	mux.HandleFunc("POST /realm/protocol/openid-connect/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.mu.Lock()
		s.revogados[r.Form.Get("token")] = true
		s.mu.Unlock()
	})
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer AT") {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":{"code":-32001,"message":"Missing or invalid token"},"jsonrpc":"2.0"}`)
			return
		}
		var msg struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&msg)
		if msg.ID == nil {
			w.WriteHeader(202)
			return
		}
		var result any
		switch msg.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			result = map[string]any{"protocolVersion": VersaoMCP}
		case "tools/list":
			if s.real {
				result = map[string]any{"tools": toolsReais}
				break
			}
			result = map[string]any{"tools": []any{
				map[string]any{"name": "listar_contas", "inputSchema": map[string]any{"properties": map[string]any{}}},
				map[string]any{"name": "consultar_saldo", "inputSchema": map[string]any{"properties": map[string]any{"accountId": map[string]any{}}}},
				map[string]any{"name": "extrato_transacoes", "inputSchema": map[string]any{
					"properties": map[string]any{"accountId": map[string]any{}, "fromBookingDate": map[string]any{}, "toBookingDate": map[string]any{}, "page": map[string]any{}},
					"required":   []string{"accountId"}}},
				map[string]any{"name": "transacoes_cartao_credito", "inputSchema": map[string]any{
					"properties": map[string]any{"creditCardAccountId": map[string]any{}}, "required": []string{"creditCardAccountId"}}},
			}}
		case "tools/call":
			if r.Header.Get("Mcp-Session-Id") != "sess-1" {
				t.Errorf("tools/call sem sessão")
			}
			if s.falhaMCP != 0 {
				w.WriteHeader(s.falhaMCP)
				s.falhaMCP = 0
				return
			}
			s.mu.Lock()
			ch := map[string]any{"_tool": msg.Params.Name}
			for k, v := range msg.Params.Arguments {
				ch[k] = v
			}
			s.chamadas = append(s.chamadas, ch)
			s.mu.Unlock()
			if s.real {
				result = toolReal(msg.Params.Name, msg.Params.Arguments)
				break
			}
			result = s.tool(t, msg.Params.Name, msg.Params.Arguments)
		}
		resp, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": *msg.ID, "result": result})
		if s.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", resp)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	})
	return mux
}

func texto(v any) map[string]any {
	b, _ := json.Marshal(v)
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(b)}}}
}

func (s *servidor) tool(t *testing.T, nome string, args map[string]any) any {
	switch nome {
	case "listar_contas":
		return texto(map[string]any{"data": []any{
			map[string]any{"accountId": "acc-1", "brandName": "Nubank", "type": "CONTA_DEPOSITO_A_VISTA", "number": "12345678"},
			map[string]any{"creditCardAccountId": "cc-1", "brandName": "Nubank", "name": "Cartão Nubank"},
		}})
	case "extrato_transacoes":
		if args["accountId"] != "acc-1" || args["fromBookingDate"] != "2026-10-01" || args["toBookingDate"] != "2026-10-31" {
			t.Errorf("argumentos: %v", args)
		}
		pag := 1
		if p, ok := args["page"].(float64); ok {
			pag = int(p)
		}
		s.paginas++
		itens := []any{
			map[string]any{"transactionId": "t1", "completedAuthorisedPaymentType": "TRANSACAO_EFETIVADA", "creditDebitType": "CREDITO",
				"transactionName": "PIX RECEBIDO MARIA", "type": "PIX", "transactionAmount": map[string]any{"amount": "150.00", "currency": "BRL"},
				"transactionDateTime": "2026-10-10T02:30:00.000Z", "partieCnpjCpf": "11144477735", "partiePersonType": "PESSOA_NATURAL"},
			map[string]any{"transactionId": "t2", "completedAuthorisedPaymentType": "LANCAMENTO_FUTURO", "creditDebitType": "DEBITO",
				"transactionName": "AGENDADO", "type": "BOLETO", "transactionAmount": map[string]any{"amount": "10.00", "currency": "BRL"},
				"transactionDateTime": "2026-10-30T12:00:00.000Z"},
		}
		if pag == 2 {
			itens = []any{map[string]any{"transactionId": "t3", "completedAuthorisedPaymentType": "TRANSACAO_PROCESSANDO", "creditDebitType": "DEBITO",
				"transactionName": "TARIFA", "type": "TARIFA_SERVICOS_AVULSOS", "transactionAmount": map[string]any{"amount": 29.9, "currency": "BRL"},
				"transactionDateTime": "2026-10-11T12:00:00Z"}}
		}
		return texto(map[string]any{"data": itens, "meta": map[string]any{"totalPages": 2, "totalRecords": 3}, "links": map[string]any{}})
	case "transacoes_cartao_credito":
		return map[string]any{"structuredContent": map[string]any{"data": []any{
			map[string]any{"transactionId": "c1", "creditDebitType": "DEBITO", "transactionName": "MERCADO", "transactionType": "OPERACOES_CREDITO_CONTRATADAS_CARTAO",
				"brazilianAmount": map[string]any{"amount": "42.10", "currency": "BRL"}, "transactionDateTime": "2026-10-05T15:00:00Z", "payeeMCC": 5411},
		}}, "content": []any{}}
	}
	return map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "tool desconhecida"}}}
}

func sobe(t *testing.T) (*Cumbuca, *servidor) {
	s := &servidor{revogados: map[string]bool{}}
	srv := httptest.NewServer(s.handler(t))
	t.Cleanup(srv.Close)
	c := New(Config{Issuer: srv.URL + "/realm", MCPURL: srv.URL + "/mcp", ClientID: "cid", ClientSecret: "sec",
		Scopes: "openid offline_access open-finance", Agora: func() time.Time { return time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC) }})
	return c, s
}

func TestOAuth(t *testing.T) {
	c, s := sobe(t)
	ctx := context.Background()
	u, _ := c.URLAutorizacao(ctx, provedor.PedidoAutorizacao{State: "st", CodeChallenge: "ch", RedirectURI: "https://pwa/api/financeiro/oauth/callback"})
	pu, _ := url.Parse(u)
	q := pu.Query()
	if !strings.HasSuffix(pu.Path, "/protocol/openid-connect/auth") || q.Get("code_challenge_method") != "S256" ||
		q.Get("scope") != "openid offline_access open-finance" || q.Get("state") != "st" || q.Get("client_id") != "cid" {
		t.Fatalf("authorize: %s", u)
	}
	tk, err := c.TrocarCodigo(ctx, "code", "verifier", "https://pwa/cb")
	if err != nil || tk.Access != "AT1" || tk.Refresh != "RT1" || !tk.AccessExpira.Equal(time.Date(2026, 11, 8, 12, 5, 0, 0, time.UTC)) {
		t.Fatalf("troca: %+v %v", tk, err)
	}
	if _, err := c.TrocarCodigo(ctx, "usado", "v", "x"); !errors.Is(err, provedor.ErrConsentimento) {
		t.Fatalf("código usado: %v", err)
	}
	tk2, err := c.Renovar(ctx, tk)
	if err != nil || tk2.Access != "AT2" || tk2.Refresh != "RT1" {
		t.Fatalf("renovar: %+v %v", tk2, err)
	}
	if err := c.Revogar(ctx, tk); err != nil {
		t.Fatal(err)
	}
	if !s.revogados["RT1"] {
		t.Fatal("revogar deveria mandar o refresh token")
	}
	if _, err := c.Renovar(ctx, tk); !errors.Is(err, provedor.ErrConsentimento) {
		t.Fatalf("refresh revogado: %v", err)
	}
}

func TestContasETransacoes(t *testing.T) {
	for _, sse := range []bool{false, true} {
		c, s := sobe(t)
		s.sse = sse
		ctx := context.Background()
		tk := provedor.Tokens{Access: "AT1"}
		contas, err := c.Contas(ctx, tk)
		if err != nil || len(contas) != 2 {
			t.Fatalf("sse=%v contas: %+v %v", sse, contas, err)
		}
		if contas[0].IDExterno != "acc-1" || contas[0].Instituicao != "Nubank" || contas[1].Tipo != "cartao" || contas[1].IDExterno != "cartao:cc-1" {
			t.Fatalf("contas: %+v", contas)
		}
		de, ate := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
		p1, err := c.Transacoes(ctx, tk, "acc-1", de, ate, "")
		if err != nil || len(p1.Transacoes) != 1 || p1.Proximo != "2" {
			t.Fatalf("página 1: %+v %v", p1, err)
		}
		tx := p1.Transacoes[0]
		// 02:30 UTC de 10/10 é 23:30 de 09/10 em São Paulo.
		if tx.IDExterno != "t1" || tx.ValorCentavos != 15000 || tx.Direcao != provedor.Entrada || tx.Tipo != "pix" ||
			tx.Data.Day() != 9 || tx.Contraparte.Documento != "11144477735" {
			t.Fatalf("lançamento: %+v", tx)
		}
		p2, err := c.Transacoes(ctx, tk, "acc-1", de, ate, p1.Proximo)
		if err != nil || len(p2.Transacoes) != 1 || p2.Proximo != "" {
			t.Fatalf("página 2: %+v %v", p2, err)
		}
		if t3 := p2.Transacoes[0]; t3.ValorCentavos != 2990 || !t3.Pendente || t3.Tipo != "tarifa" || t3.Direcao != provedor.Saida {
			t.Fatalf("tarifa: %+v", t3)
		}
		pc, err := c.Transacoes(ctx, tk, "cartao:cc-1", de, ate, "")
		if err != nil || len(pc.Transacoes) != 1 || pc.Transacoes[0].Tipo != "cartao" || pc.Transacoes[0].ValorCentavos != 4210 {
			t.Fatalf("cartão: %+v %v", pc, err)
		}
	}
}

func TestErrosMCP(t *testing.T) {
	c, s := sobe(t)
	ctx := context.Background()
	if _, err := c.Contas(ctx, provedor.Tokens{Access: "invalido"}); !errors.Is(err, provedor.ErrConsentimento) {
		t.Fatalf("401: %v", err)
	}
	tk := provedor.Tokens{Access: "AT1"}
	s.falhaMCP = 429
	if _, err := c.Contas(ctx, tk); err == nil {
		t.Fatal("esperava 429")
	} else if _, ok := provedor.ComoLimite(err); !ok {
		t.Fatalf("429: %v", err)
	}
	s.falhaMCP = 503
	if _, err := c.Contas(ctx, tk); !errors.Is(err, provedor.ErrTransitorio) {
		t.Fatalf("503: %v", err)
	}
}

func TestMapeamentoRecusaFormatoInesperado(t *testing.T) {
	casos := map[string]map[string]any{
		"sem valor":       {"creditDebitType": "CREDITO", "transactionDateTime": "2026-10-01T10:00:00Z"},
		"moeda":           {"creditDebitType": "CREDITO", "transactionAmount": map[string]any{"amount": "1", "currency": "USD"}, "transactionDateTime": "2026-10-01T10:00:00Z"},
		"três casas":      {"creditDebitType": "CREDITO", "transactionAmount": map[string]any{"amount": "1.005"}, "transactionDateTime": "2026-10-01T10:00:00Z"},
		"sem data":        {"creditDebitType": "CREDITO", "transactionAmount": map[string]any{"amount": "1"}},
		"sem crédito/déb": {"transactionAmount": map[string]any{"amount": "1"}, "transactionDateTime": "2026-10-01T10:00:00Z"},
	}
	for nome, m := range casos {
		if _, _, err := transacao(m, false); !errors.Is(err, provedor.ErrResposta) {
			t.Errorf("%s: esperava ErrResposta, veio %v", nome, err)
		}
	}
	// Valor negativo sem indicador = débito.
	tx, ok, err := transacao(map[string]any{"amount": -12.5, "date": "2026-10-01", "description": "X"}, false)
	if err != nil || !ok || tx.Direcao != provedor.Saida || tx.ValorCentavos != 1250 {
		t.Fatalf("negativo: %+v %v", tx, err)
	}
}

func TestRegistrar(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/realm/clients-registrations/openid-connect" || !strings.Contains(string(b), "https://pwa/cb") {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(201)
		fmt.Fprint(w, `{"client_id":"novo","client_secret":"s3"}`)
	}))
	defer srv.Close()
	r, err := Registrar(context.Background(), srv.Client(), srv.URL+"/realm", "App", []string{"https://pwa/cb"}, "openid")
	if err != nil || r.ClientID != "novo" || r.ClientSecret != "s3" {
		t.Fatalf("%+v %v", r, err)
	}
}
