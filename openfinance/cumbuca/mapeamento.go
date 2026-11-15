package cumbuca

import (
	"context"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	provedor "github.com/thiagoB-Labs/labs-kit/openfinance"
)

var fuso = func() *time.Location {
	l, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		panic(err)
	}
	return l
}()

// Contas implementa provedor.Provedor: contas de depósito e de cartão.
func (c *Cumbuca) Contas(ctx context.Context, t provedor.Tokens) ([]provedor.Conta, error) {
	tools, err := c.Tools(ctx, t.Access)
	if err != nil {
		return nil, err
	}
	tool, ok := toolContas(tools)
	if !ok {
		return nil, fmt.Errorf("%w: nenhuma tool de contas em tools/list", provedor.ErrResposta)
	}
	args, err := argumentos(tool, map[string]any{})
	if err != nil {
		return nil, err
	}
	dado, err := c.chamaTool(ctx, t.Access, tool.Name, args)
	if err != nil {
		return nil, err
	}
	itens := lista(dado, "accountId", "creditCardAccountId", "id")
	var out []provedor.Conta
	for _, it := range itens {
		ct, ok := conta(it)
		if !ok {
			continue
		}
		if ct.Tipo != "cartao" {
			ct.SaldoCentavos, ct.SaldoEm = c.saldo(ctx, t, tools, ct.IDExterno)
		}
		out = append(out, ct)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: nenhuma conta reconhecível", provedor.ErrResposta)
	}
	return out, nil
}

// saldo é opcional: sem tool, sem resposta ou fora do formato, a conta fica sem saldo (o fin nunca
// calcula saldo por conta própria) e a sincronização segue.
func (c *Cumbuca) saldo(ctx context.Context, t provedor.Tokens, tools []Tool, conta string) (*int64, *time.Time) {
	tool, ok := toolSaldo(tools)
	p := achaParam(tool, nomesConta)
	if !ok || p == "" {
		return nil, nil
	}
	args, err := argumentos(tool, map[string]any{p: conta})
	if err != nil {
		return nil, nil
	}
	dado, err := c.chamaTool(ctx, t.Access, tool.Name, args)
	if err != nil {
		return nil, nil
	}
	m, _ := dado.(map[string]any)
	if b, ok := m["balance"].(map[string]any); ok {
		m = b
	}
	disp, _ := m["availableAmount"].(map[string]any)
	if moeda := str(disp, "currency"); moeda != "" && moeda != "BRL" {
		return nil, nil
	}
	v, err := decimalCentavos(str(disp, "amount"))
	if err != nil {
		return nil, nil
	}
	em := c.cfg.Agora().UTC()
	if s := str(m, "updateDateTime"); s != "" {
		if x, err := time.Parse(time.RFC3339Nano, s); err == nil {
			em = x.UTC()
		}
	}
	return &v, &em
}

// decimalCentavos lê "1234.56" (com sinal, zero permitido) sem ponto flutuante.
func decimalCentavos(s string) (int64, error) {
	r, ok := new(big.Rat).SetString(strings.TrimSpace(s))
	if !ok || s == "" {
		return 0, fmt.Errorf("%w: valor ilegível", provedor.ErrResposta)
	}
	r.Mul(r, big.NewRat(100, 1))
	if !r.IsInt() || !r.Num().IsInt64() {
		return 0, fmt.Errorf("%w: valor com mais de 2 casas", provedor.ErrResposta)
	}
	return r.Num().Int64(), nil
}

// Janela implementa provedor.Janela. Na Cumbuca, cada usuário tem cota mensal: o extrato dos
// últimos 7 dias tem 240 pedidos/mês, e qualquer período mais antigo, só 8. Por isso a
// sincronização revisita 5 dias (fica dentro dos 7) e pede o histórico inicial num pedido só.
func (c *Cumbuca) Janela() (sobreposicaoDias, diasPorBloco int) { return 5, 400 }

// MaxMesesHistorico é o limite da Cumbuca para o início do período.
const MaxMesesHistorico = 12

func conta(m map[string]any) (provedor.Conta, bool) {
	id := str(m, "accountId", "creditCardAccountId", "id")
	if id == "" {
		return provedor.Conta{}, false
	}
	tipo := "corrente"
	switch strings.ToUpper(str(m, "type", "accountType", "tipo")) {
	case "CONTA_POUPANCA":
		tipo = "poupanca"
	case "CONTA_PAGAMENTO_PRE_PAGA":
		tipo = "pagamento"
	}
	if _, ok := m["creditCardAccountId"]; ok || strings.Contains(strings.ToLower(str(m, "productType", "name")), "cart") {
		tipo = "cartao"
	}
	if tipo == "cartao" {
		id = "cartao:" + id // Transacoes usa a tool de cartão
	}
	nome := str(m, "name", "productName", "nome")
	if nome == "" {
		nome = nomesTipo[tipo]
	}
	return provedor.Conta{
		IDExterno: id, Tipo: tipo, Nome: nome, Final: final(str(m, "number", "numero", "accountNumber")),
		Instituicao: instituicao(str(m, "compeCode"), str(m, "brandName", "institutionName", "bankName", "instituicao")),
		TitularDoc:  str(m, "holderDocument", "cpf", "document"),
	}, true
}

var nomesTipo = map[string]string{
	"corrente": "Conta corrente", "poupanca": "Poupança", "pagamento": "Conta de pagamento", "cartao": "Cartão de crédito",
}

// final: os 4 últimos dígitos do número da conta (nunca o número inteiro na tela).
func final(numero string) string {
	d := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, numero)
	if len(d) > 4 {
		d = d[len(d)-4:]
	}
	return d
}

// Nomes de exibição pelo código COMPE: o brandName da Cumbuca vem em minúsculas ("itau").
var bancos = map[string]string{
	"001": "Banco do Brasil", "033": "Santander", "077": "Inter", "104": "Caixa", "208": "BTG Pactual",
	"212": "Banco Original", "237": "Bradesco", "260": "Nubank", "290": "PagBank", "323": "Mercado Pago",
	"336": "C6 Bank", "341": "Itaú", "380": "PicPay", "403": "Cora", "422": "Safra", "748": "Sicredi", "756": "Sicoob",
}

func instituicao(compe, marca string) string {
	if n, ok := bancos[compe]; ok {
		return n
	}
	if marca != "" && marca == strings.ToLower(marca) {
		r := []rune(marca)
		return strings.ToUpper(string(r[0])) + string(r[1:])
	}
	return marca
}

// Transacoes implementa provedor.Provedor. A conta de cartão usa a tool de cartão.
func (c *Cumbuca) Transacoes(ctx context.Context, t provedor.Tokens, conta string, de, ate time.Time, cursor string) (provedor.Pagina, error) {
	tools, err := c.Tools(ctx, t.Access)
	if err != nil {
		return provedor.Pagina{}, err
	}
	tool, ok := toolTransacoes(tools, false)
	cartao := strings.HasPrefix(conta, "cartao:")
	if cartao {
		conta = strings.TrimPrefix(conta, "cartao:")
		tool, ok = toolTransacoes(tools, true)
	}
	if !ok {
		return provedor.Pagina{}, fmt.Errorf("%w: nenhuma tool de transações em tools/list", provedor.ErrResposta)
	}
	if lim := c.inicioMaximo(); de.Before(lim) {
		de = lim
	}
	v := map[string]any{}
	if p := achaParam(tool, nomesConta); p != "" {
		v[p] = conta
	}
	if p := achaParam(tool, nomesDe); p != "" {
		v[p] = de.Format(time.DateOnly)
	}
	if p := achaParam(tool, nomesAte); p != "" {
		v[p] = ate.Format(time.DateOnly)
	}
	pagParam := achaParam(tool, nomesPagina)
	if pagParam != "" && cursor != "" {
		if n, err := strconv.Atoi(cursor); err == nil && strings.Contains(strings.ToLower(pagParam), "pag") {
			v[pagParam] = n
		} else {
			v[pagParam] = cursor
		}
	}
	args, err := argumentos(tool, v)
	if err != nil {
		return provedor.Pagina{}, err
	}
	dado, err := c.chamaTool(ctx, t.Access, tool.Name, args)
	if err != nil {
		return provedor.Pagina{}, err
	}
	var p provedor.Pagina
	for _, it := range lista(dado, "transactionId", "creditDebitType", "transactionAmount", "amount", "brazilianAmount") {
		tx, incluir, err := transacao(it, cartao)
		if err != nil {
			return provedor.Pagina{}, err
		}
		if incluir {
			p.Transacoes = append(p.Transacoes, tx)
		}
	}
	p.Proximo = proxima(dado, pagParam, cursor)
	return p, nil
}

// inicioMaximo é o dia mais antigo que a Cumbuca aceita (12 meses para trás, no fuso de SP).
func (c *Cumbuca) inicioMaximo() time.Time {
	h := c.cfg.Agora().In(fuso)
	return time.Date(h.Year(), h.Month(), h.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, -MaxMesesHistorico, 1)
}

// transacao converte um lançamento no padrão Open Finance Brasil (contas e cartões).
// incluir=false para lançamentos futuros (agendados), que ainda não aconteceram.
func transacao(m map[string]any, cartao bool) (provedor.Transacao, bool, error) {
	if strings.ToUpper(str(m, "completedAuthorisedPaymentType")) == "LANCAMENTO_FUTURO" {
		return provedor.Transacao{}, false, nil
	}
	valor, negativo, err := centavos(m)
	if err != nil {
		return provedor.Transacao{}, false, err
	}
	dir := provedor.Entrada
	switch strings.ToUpper(str(m, "creditDebitType", "creditDebitIndicator", "type_direction")) {
	case "DEBITO", "DEBIT", "D":
		dir = provedor.Saida
	case "CREDITO", "CREDIT", "C":
	default:
		if !negativo {
			return provedor.Transacao{}, false, fmt.Errorf("%w: lançamento sem crédito/débito", provedor.ErrResposta)
		}
		dir = provedor.Saida
	}
	quando, dataHora, err := data(m)
	if err != nil {
		return provedor.Transacao{}, false, err
	}
	tx := provedor.Transacao{
		IDExterno: str(m, "transactionId", "id"), Data: quando, DataHora: dataHora, ValorCentavos: valor, Direcao: dir,
		Tipo: tipo(m, cartao), Pendente: strings.ToUpper(str(m, "completedAuthorisedPaymentType")) == "TRANSACAO_PROCESSANDO",
		Descricao: str(m, "transactionName", "description", "descricao"),
		Contraparte: provedor.Contraparte{
			Nome:      str(m, "partieName", "counterpartyName", "payeeName", "nomeContraparte"),
			Documento: str(m, "partieCnpjCpf", "counterpartyDocument"),
			ISPB:      str(m, "codeISPB", "partieCompeCode"), Agencia: str(m, "partieBranchCode"),
			Conta: strings.TrimSpace(str(m, "partieNumber") + str(m, "partieCheckDigit")),
		},
	}
	if tx.Contraparte.Nome == "" {
		tx.Contraparte.Nome = nomeNaDescricao(tx.Descricao)
	}
	if tx.Contraparte.Nome == "" && tx.Contraparte.Documento == "" && tx.Contraparte.Conta == "" {
		tx.Contraparte.Nome = str(m, "payeeMCC") // compras de cartão: o estabelecimento vem na descrição
	}
	tx.Propria = tx.Contraparte.Documento == "" && tx.Contraparte.Conta == "" && reAplicacao.MatchString(tx.Descricao)
	return tx, true, tx.Valida()
}

// Prefixos com que os bancos descrevem o lançamento antes do nome de quem está do outro lado (a
// Cumbuca não manda partieName): "Pix recebido FULANA", "Pagamento de boleto EMPRESA".
var prefixosContraparte = []string{
	"pix recebido de ", "pix recebido ", "pix enviado para ", "pix enviado ", "pagamento de pix qr code ", "pix qr code ",
	"pagamento de boleto ", "ted recebida ", "ted enviada ", "transferencia recebida ", "transferência recebida ",
	"transferencia enviada ", "transferência enviada ",
}

func nomeNaDescricao(desc string) string {
	baixa := strings.ToLower(desc)
	for _, p := range prefixosContraparte {
		if strings.HasPrefix(baixa, p) {
			return strings.TrimSpace(desc[len(p):])
		}
	}
	return ""
}

// Aplicação e resgate automáticos sem contraparte ("Saída APLICACAO COFRINHOS", "Resgate
// COFRINHOS"): o dinheiro continua do titular (F5.1 c).
var reAplicacao = regexp.MustCompile(`(?i)\b(aplica[cç][aã]o|resgate|cofrinhos?|caixinhas?|porquinho)\b`)

func tipo(m map[string]any, cartao bool) string {
	t := strings.ToUpper(str(m, "type", "transactionType"))
	if cartao {
		switch t {
		case "TARIFA":
			return "tarifa"
		case "ESTORNO":
			return "estorno"
		case "PAGAMENTO":
			return "outro" // pagamento da fatura
		}
		return "cartao"
	}
	switch t {
	case "PIX":
		return "pix"
	case "TED", "DOC", "TRANSFERENCIA_MESMA_INSTITUICAO", "PORTABILIDADE_SALARIO":
		return "ted_doc"
	case "BOLETO", "CONVENIO_ARRECADACAO":
		return "boleto"
	case "PACOTE_TARIFA_SERVICOS", "TARIFA_SERVICOS_AVULSOS", "ENCARGOS_JUROS_CHEQUE_ESPECIAL":
		return "tarifa"
	case "DEPOSITO":
		return "deposito"
	case "SAQUE":
		return "saque"
	case "CARTAO":
		return "cartao"
	case "RENDIMENTO_APLIC_FINANCEIRA":
		return "rendimento"
	case "ESTORNO":
		return "estorno"
	}
	return "outro"
}

// centavos lê transactionAmount.amount / brazilianAmount.amount / amount (string ou número)
// sem ponto flutuante.
func centavos(m map[string]any) (int64, bool, error) {
	var bruto any
	for _, k := range []string{"transactionAmount", "brazilianAmount", "amount", "valor"} {
		if v, ok := m[k]; ok {
			if sub, ok := v.(map[string]any); ok {
				if moeda := str(sub, "currency"); moeda != "" && moeda != "BRL" {
					return 0, false, fmt.Errorf("%w: moeda %s", provedor.ErrResposta, moeda)
				}
				bruto = sub["amount"]
			} else {
				bruto = v
			}
			break
		}
	}
	s := strings.TrimSpace(fmt.Sprint(bruto))
	if bruto == nil || s == "" {
		return 0, false, fmt.Errorf("%w: lançamento sem valor", provedor.ErrResposta)
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return 0, false, fmt.Errorf("%w: valor ilegível", provedor.ErrResposta)
	}
	neg := r.Sign() < 0
	r.Abs(r).Mul(r, big.NewRat(100, 1))
	if !r.IsInt() {
		return 0, false, fmt.Errorf("%w: valor com mais de 2 casas", provedor.ErrResposta)
	}
	if !r.Num().IsInt64() || r.Num().Int64() == 0 {
		return 0, false, fmt.Errorf("%w: valor fora da faixa", provedor.ErrResposta)
	}
	return r.Num().Int64(), neg, nil
}

func data(m map[string]any) (time.Time, *time.Time, error) {
	if s := str(m, "transactionDateTime", "dateTime", "dataHora"); s != "" {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05"} {
			if t, err := time.Parse(layout, s); err == nil {
				local := t.In(fuso)
				d := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
				u := t.UTC()
				return d, &u, nil
			}
		}
	}
	if s := str(m, "bookingDate", "transactionDate", "billPostDate", "date", "data"); s != "" {
		if t, err := time.Parse(time.DateOnly, s[:min(10, len(s))]); err == nil {
			return t, nil, nil
		}
	}
	return time.Time{}, nil, fmt.Errorf("%w: lançamento sem data", provedor.ErrResposta)
}

// lista acha a lista de objetos de dados: a raiz, ou "data"/"items"/..., ou o primeiro array de
// objetos que tenha alguma das chaves esperadas.
func lista(v any, chaves ...string) []map[string]any {
	switch x := v.(type) {
	case []any:
		var out []map[string]any
		for _, it := range x {
			if m, ok := it.(map[string]any); ok && temAlguma(m, chaves) {
				out = append(out, m)
			}
		}
		if len(out) > 0 {
			return out
		}
	case map[string]any:
		if temAlguma(x, chaves) {
			return []map[string]any{x}
		}
		for _, k := range []string{"data", "items", "transactions", "accounts", "resources", "results"} {
			if l := lista(x[k], chaves...); len(l) > 0 {
				return l
			}
		}
		for _, sub := range x {
			if l := lista(sub, chaves...); len(l) > 0 {
				return l
			}
		}
	}
	return nil
}

func temAlguma(m map[string]any, chaves []string) bool {
	for _, k := range chaves {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// proxima lê a paginação: cursor explícito, links.next do Open Finance ou meta.totalPages.
func proxima(v any, param, atual string) string {
	m, ok := v.(map[string]any)
	if !ok || param == "" {
		return ""
	}
	for _, k := range []string{"nextCursor", "next_cursor", "nextPageToken", "cursor"} {
		if s := str(m, k); s != "" && s != atual {
			return s
		}
	}
	meta, _ := m["meta"].(map[string]any)
	links, _ := m["links"].(map[string]any)
	total, _ := strconv.Atoi(str(meta, "totalPages"))
	pag := 1
	if n, err := strconv.Atoi(atual); err == nil {
		pag = n
	}
	if total > pag || (total == 0 && str(links, "next") != "") {
		return strconv.Itoa(pag + 1)
	}
	return ""
}

func str(m map[string]any, chaves ...string) string {
	for _, k := range chaves {
		switch x := m[k].(type) {
		case string:
			if x != "" {
				return x
			}
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(x)
		}
	}
	return ""
}
