package cumbuca

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	provedor "github.com/thiagoB-Labs/labs-kit/openfinance"
)

// VersaoMCP é a versão do protocolo anunciada no initialize.
const VersaoMCP = "2025-06-18"

var proximoID atomic.Int64

type rpcErro struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResposta struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcErro        `json:"error"`
}

// sessao abre uma sessão MCP com o token do profissional (initialize + initialized).
func (c *Cumbuca) sessao(ctx context.Context, token string) (string, error) {
	params := map[string]any{"protocolVersion": VersaoMCP, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": c.cfg.NomeCliente, "version": "1"}}
	sid, _, err := c.rpc(ctx, token, "", "initialize", params, true)
	if err != nil {
		return "", err
	}
	if _, _, err := c.rpc(ctx, token, sid, "notifications/initialized", nil, false); err != nil {
		return "", err
	}
	return sid, nil
}

// rpc envia uma requisição JSON-RPC (ou notificação, se comResposta=false) e devolve o
// Mcp-Session-Id e o result.
func (c *Cumbuca) rpc(ctx context.Context, token, sid, metodo string, params any, comResposta bool) (string, json.RawMessage, error) {
	msg := map[string]any{"jsonrpc": "2.0", "method": metodo}
	if params != nil {
		msg["params"] = params
	}
	id := proximoID.Add(1)
	if comResposta {
		msg["id"] = id
	}
	corpo, _ := json.Marshal(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.MCPURL, bytes.NewReader(corpo))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("MCP-Protocol-Version", VersaoMCP)
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", provedor.ErrTransitorio, semURL(err))
	}
	defer resp.Body.Close()
	if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
		sid = s
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return sid, nil, fmt.Errorf("%w: MCP HTTP %d", provedor.ErrConsentimento, resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return sid, nil, limite(resp.Header)
	case resp.StatusCode >= 500:
		return sid, nil, fmt.Errorf("%w: MCP HTTP %d", provedor.ErrTransitorio, resp.StatusCode)
	case resp.StatusCode == http.StatusAccepted && !comResposta:
		return sid, nil, nil
	case resp.StatusCode >= 300:
		return sid, nil, fmt.Errorf("%w: MCP HTTP %d", provedor.ErrResposta, resp.StatusCode)
	}
	if !comResposta {
		return sid, nil, nil
	}
	r, err := lerResposta(resp, id)
	if err != nil {
		return sid, nil, err
	}
	if r.Error != nil {
		return sid, nil, erroRPC(r.Error)
	}
	return sid, r.Result, nil
}

func erroRPC(e *rpcErro) error {
	switch e.Code {
	case -32001: // "Missing or invalid token" (visto no servidor)
		return fmt.Errorf("%w: rpc %d", provedor.ErrConsentimento, e.Code)
	case -32603:
		return fmt.Errorf("%w: rpc %d", provedor.ErrTransitorio, e.Code)
	}
	return fmt.Errorf("%w: rpc %d", provedor.ErrResposta, e.Code)
}

// lerResposta aceita application/json ou um stream SSE com a resposta de mesmo id.
func lerResposta(resp *http.Response, id int64) (rpcResposta, error) {
	var r rpcResposta
	corpo := io.LimitReader(resp.Body, 32<<20)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		if err := json.NewDecoder(corpo).Decode(&r); err != nil {
			return r, fmt.Errorf("%w: JSON-RPC ilegível", provedor.ErrResposta)
		}
		return r, nil
	}
	sc := bufio.NewScanner(corpo)
	sc.Buffer(make([]byte, 0, 64<<10), 32<<20)
	var dados strings.Builder
	quer := fmt.Sprint(id)
	tenta := func() bool {
		if dados.Len() == 0 {
			return false
		}
		var x rpcResposta
		err := json.Unmarshal([]byte(dados.String()), &x)
		dados.Reset()
		if err == nil && string(x.ID) == quer {
			r = x
			return true
		}
		return false
	}
	for sc.Scan() {
		linha := sc.Text()
		if v, ok := strings.CutPrefix(linha, "data:"); ok {
			dados.WriteString(strings.TrimPrefix(v, " "))
			continue
		}
		if linha == "" && tenta() {
			return r, nil
		}
	}
	if tenta() {
		return r, nil
	}
	return r, fmt.Errorf("%w: stream SSE sem resposta", provedor.ErrTransitorio)
}

// ---------------------------------------------------------------- catálogo de tools

// Tool é uma entrada de tools/list.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	} `json:"inputSchema"`
}

type catalogo struct {
	mu    sync.Mutex
	tools []Tool
}

// Tools lista (e guarda) as tools do servidor.
func (c *Cumbuca) Tools(ctx context.Context, token string) ([]Tool, error) {
	c.tools.mu.Lock()
	defer c.tools.mu.Unlock()
	if c.tools.tools != nil {
		return c.tools.tools, nil
	}
	sid, err := c.sessao(ctx, token)
	if err != nil {
		return nil, err
	}
	_, res, err := c.rpc(ctx, token, sid, "tools/list", map[string]any{}, true)
	if err != nil {
		return nil, err
	}
	var l struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(res, &l); err != nil || len(l.Tools) == 0 {
		return nil, fmt.Errorf("%w: tools/list vazio", provedor.ErrResposta)
	}
	c.tools.tools = l.Tools
	return l.Tools, nil
}

var (
	reContas = regexp.MustCompile(`(?i)(account|conta)`)
	reTrans  = regexp.MustCompile(`(?i)(transac|extrato|statement|lancamento|lançamento)`)
	reCartao = regexp.MustCompile(`(?i)(card|cartao|cartão|credit)`)
	reSaldo  = regexp.MustCompile(`(?i)(balance|saldo)`)
)

// escolhe a tool pelo nome (e, se nenhum nome servir, pela descrição). Entre várias candidatas,
// fica a que exige menos parâmetros: "list_accounts" ganha de "get_account(account_id)".
func escolhe(tools []Tool, quer func(string) bool) (Tool, bool) {
	for _, campo := range []func(Tool) string{func(t Tool) string { return t.Name }, func(t Tool) string { return t.Description }} {
		melhor, achou := Tool{}, false
		for _, t := range tools {
			if quer(campo(t)) && (!achou || len(t.InputSchema.Required) < len(melhor.InputSchema.Required)) {
				melhor, achou = t, true
			}
		}
		if achou {
			return melhor, true
		}
	}
	return Tool{}, false
}

func toolContas(ts []Tool) (Tool, bool) {
	return escolhe(ts, func(s string) bool {
		return reContas.MatchString(s) && !reTrans.MatchString(s) && !reSaldo.MatchString(s) && !reCartao.MatchString(s)
	})
}

// toolSaldo: na Cumbuca é get_account, que só fala de saldo na descrição.
func toolSaldo(ts []Tool) (Tool, bool) {
	return escolhe(ts, func(s string) bool {
		return reSaldo.MatchString(s) && !reTrans.MatchString(s) && !reCartao.MatchString(s)
	})
}

func toolTransacoes(ts []Tool, cartao bool) (Tool, bool) {
	return escolhe(ts, func(s string) bool { return reTrans.MatchString(s) && reCartao.MatchString(s) == cartao })
}

// Nomes de parâmetro reconhecidos (padrão Open Finance e variações).
var (
	nomesConta  = []string{"accountId", "account_id", "accountID", "creditCardAccountId", "credit_card_account_id", "contaId", "conta_id", "id_conta", "account"}
	nomesDe     = []string{"fromBookingDate", "fromTransactionDate", "from_date", "fromDate", "start_date", "startDate", "dataInicio", "data_inicio", "inicio", "de", "from", "start"}
	nomesAte    = []string{"toBookingDate", "toTransactionDate", "to_date", "toDate", "end_date", "endDate", "dataFim", "data_fim", "fim", "ate", "to", "end"}
	nomesPagina = []string{"page", "pagina", "cursor", "pageToken", "page_token", "next"}
)

func achaParam(t Tool, nomes []string) string {
	for _, n := range nomes {
		for p := range t.InputSchema.Properties {
			if strings.EqualFold(p, n) {
				return p
			}
		}
	}
	return ""
}

// argumentos monta os argumentos e confere que todos os obrigatórios foram preenchidos.
func argumentos(t Tool, valores map[string]any) (map[string]any, error) {
	for _, r := range t.InputSchema.Required {
		if _, ok := valores[r]; !ok {
			return nil, fmt.Errorf("%w: tool %s exige %q, que o adapter não sabe preencher", provedor.ErrResposta, t.Name, r)
		}
	}
	return valores, nil
}

// chamaTool executa tools/call e devolve o JSON de dados (structuredContent ou o texto).
func (c *Cumbuca) chamaTool(ctx context.Context, token, nome string, args map[string]any) (any, error) {
	sid, err := c.sessao(ctx, token)
	if err != nil {
		return nil, err
	}
	_, res, err := c.rpc(ctx, token, sid, "tools/call", map[string]any{"name": nome, "arguments": args}, true)
	if err != nil {
		return nil, err
	}
	var r struct {
		IsError           bool            `json:"isError"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		Content           []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, fmt.Errorf("%w: resultado da tool", provedor.ErrResposta)
	}
	if r.IsError {
		texto := ""
		for _, c := range r.Content {
			texto += " " + c.Text
		}
		t := strings.ToLower(texto)
		if strings.Contains(t, "consent") || strings.Contains(t, "autoriz") || strings.Contains(t, "expir") || strings.Contains(t, "revog") {
			return nil, fmt.Errorf("%w: tool %s", provedor.ErrConsentimento, nome)
		}
		return nil, fmt.Errorf("%w: tool %s devolveu erro", provedor.ErrTransitorio, nome)
	}
	var dado any
	if len(r.StructuredContent) > 0 && string(r.StructuredContent) != "null" {
		if err := json.Unmarshal(r.StructuredContent, &dado); err == nil {
			return dado, nil
		}
	}
	for _, ct := range r.Content {
		if ct.Type != "text" {
			continue
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(ct.Text)), &dado); err == nil {
			return dado, nil
		}
	}
	return nil, fmt.Errorf("%w: tool %s sem JSON", provedor.ErrResposta, nome)
}
