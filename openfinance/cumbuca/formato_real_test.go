package cumbuca

import (
	"context"
	"testing"
	"time"

	provedor "github.com/thiagoB-Labs/labs-kit/openfinance"
)

// Tools e formato observados no MCP da Cumbuca em 2026-11 (nomes, descrições resumidas, schemas e
// forma das respostas). Valores inventados.
var toolsReais = []any{
	// get_account vem antes de list_accounts de propósito: a escolha não pode depender da ordem.
	tool("get_account", "Returns details and current balance for a single account.", []string{"account_id"}, "account_id", "bypass_cache"),
	tool("get_consent_status", "Returns the current status of the user's consent.", nil),
	tool("list_account_transactions", "Returns transaction history for a given account.", []string{"account_id"}, "account_id", "bypass_cache", "from_date", "to_date"),
	tool("list_accounts", "Lists all bank accounts for the authorized financial institution.", nil, "bypass_cache"),
	tool("list_credit_card_bill_transactions", "Returns transactions for a specific credit card bill.", []string{"credit_card_account_id", "bill_id"}, "credit_card_account_id", "bill_id"),
	tool("list_credit_card_bills", "Returns the list of bills (faturas) for a credit card account.", []string{"credit_card_account_id"}, "credit_card_account_id"),
	tool("list_credit_cards", "Lists all credit card accounts for the authorized institution.", nil),
	tool("revoke_consent", "Permanently revokes the user's current Open Finance consent.", nil),
}

func tool(nome, desc string, obrigatorios []string, props ...string) map[string]any {
	p := map[string]any{}
	for _, x := range props {
		p[x] = map[string]any{"type": "string"}
	}
	return map[string]any{"name": nome, "description": desc, "inputSchema": map[string]any{"type": "object", "properties": p, "required": obrigatorios}}
}

func toolReal(nome string, args map[string]any) any {
	switch nome {
	case "list_accounts":
		return texto(map[string]any{"accounts": []any{map[string]any{
			"accountId": "acc-real", "branchCode": "0001", "brandName": "itau", "checkDigit": "9", "companyCnpj": "60701190000104",
			"compeCode": "341", "number": "00012345", "type": "CONTA_DEPOSITO_A_VISTA"}}})
	case "get_account":
		return texto(map[string]any{
			"account": map[string]any{"branchCode": "0001", "compeCode": "341", "currency": "BRL", "number": "00012345", "type": "CONTA_DEPOSITO_A_VISTA"},
			"balance": map[string]any{"availableAmount": map[string]any{"amount": "1234.56", "currency": "BRL"},
				"blockedAmount": map[string]any{"amount": "0.00", "currency": "BRL"}, "updateDateTime": "2026-11-08T16:32:12Z"}})
	case "list_account_transactions":
		return texto(map[string]any{"transactions": []any{
			map[string]any{"codeISPB": "18236120", "completedAuthorisedPaymentType": "TRANSACAO_EFETIVADA", "creditDebitType": "CREDITO",
				"partieCnpjCpf": "11144477735", "partieCompeCode": "260", "transactionAmount": map[string]any{"amount": "200.00", "currency": "BRL"},
				"transactionDateTime": "2026-11-05T13:45:06.027Z", "transactionId": "r1", "transactionName": "Pix recebido MARIA DA SILVA", "type": "PIX"},
			map[string]any{"completedAuthorisedPaymentType": "TRANSACAO_EFETIVADA", "creditDebitType": "DEBITO",
				"transactionAmount": map[string]any{"amount": "200.00", "currency": "BRL"}, "transactionDateTime": "2026-11-05T19:38:02.011Z",
				"transactionId": "r2", "transactionName": "Saída APLICACAO COFRINHOS", "type": "OUTROS", "typeAdditionalInfo": "Saída"},
			map[string]any{"completedAuthorisedPaymentType": "TRANSACAO_EFETIVADA", "creditDebitType": "CREDITO",
				"transactionAmount": map[string]any{"amount": "50.01", "currency": "BRL"}, "transactionDateTime": "2026-10-26T00:28:21.093Z",
				"transactionId": "r3", "transactionName": "Entrada RESGATE COFRINHOS", "type": "OUTROS", "typeAdditionalInfo": "Entrada"},
			map[string]any{"codeISPB": "00416968", "completedAuthorisedPaymentType": "TRANSACAO_EFETIVADA", "creditDebitType": "DEBITO",
				"partieCnpjCpf": "11222333000181", "partieCompeCode": "077", "transactionAmount": map[string]any{"amount": "300.00", "currency": "BRL"},
				"transactionDateTime": "2026-10-20T19:29:46.097Z", "transactionId": "r4", "transactionName": "Pagamento de boleto ALUGUEL SALA LTDA", "type": "BOLETO"},
			map[string]any{"codeISPB": "16501555", "completedAuthorisedPaymentType": "TRANSACAO_EFETIVADA", "creditDebitType": "DEBITO",
				"partieCnpjCpf": "11222333000181", "partieCompeCode": "197", "transactionAmount": map[string]any{"amount": "33.97", "currency": "BRL"},
				"transactionDateTime": "2026-10-23T22:12:12.069Z", "transactionId": "r5", "transactionName": "Pagamento de Pix QR Code MERCADO X", "type": "PIX"},
		}})
	}
	return map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "tool desconhecida"}}}
}

func TestFormatoRealDaCumbuca(t *testing.T) {
	c, s := sobe(t)
	s.real = true
	ctx := context.Background()
	tk := provedor.Tokens{Access: "AT1"}

	contas, err := c.Contas(ctx, tk)
	if err != nil || len(contas) != 1 {
		t.Fatalf("contas: %+v %v", contas, err)
	}
	ct := contas[0]
	if ct.IDExterno != "acc-real" || ct.Tipo != "corrente" || ct.Nome != "Conta corrente" || ct.Final != "2345" || ct.Instituicao != "Itaú" {
		t.Fatalf("conta: %+v", ct)
	}
	if ct.SaldoCentavos == nil || *ct.SaldoCentavos != 123456 || ct.SaldoEm == nil || ct.SaldoEm.Hour() != 16 {
		t.Fatalf("saldo: %v %v", ct.SaldoCentavos, ct.SaldoEm)
	}
	if s.chamadas[0]["_tool"] != "list_accounts" || s.chamadas[1]["_tool"] != "get_account" || s.chamadas[1]["account_id"] != "acc-real" {
		t.Fatalf("tools chamadas: %v", s.chamadas)
	}
	for _, ch := range s.chamadas {
		if ch["bypass_cache"] != nil {
			t.Fatalf("nunca pode pular o cache (gasta a cota do usuário): %v", ch)
		}
	}

	// Histórico pedido além de 12 meses é limitado ao que a Cumbuca aceita.
	s.chamadas = nil
	p, err := c.Transacoes(ctx, tk, "acc-real", time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC), "")
	if err != nil || p.Proximo != "" || len(p.Transacoes) != 5 {
		t.Fatalf("transações: %+v %v", p, err)
	}
	if ch := s.chamadas[0]; ch["_tool"] != "list_account_transactions" || ch["account_id"] != "acc-real" ||
		ch["from_date"] != "2025-11-09" || ch["to_date"] != "2026-11-08" {
		t.Fatalf("argumentos: %v", ch)
	}
	pix, aplic, resg, boleto, qr := p.Transacoes[0], p.Transacoes[1], p.Transacoes[2], p.Transacoes[3], p.Transacoes[4]
	if pix.Contraparte.Nome != "MARIA DA SILVA" || pix.Contraparte.Documento != "11144477735" || pix.Contraparte.ISPB != "18236120" ||
		pix.Propria || pix.Direcao != provedor.Entrada || pix.Tipo != "pix" || pix.ValorCentavos != 20000 {
		t.Fatalf("pix: %+v", pix)
	}
	if !aplic.Propria || aplic.Direcao != provedor.Saida || aplic.Contraparte.Nome != "" || !resg.Propria || resg.Direcao != provedor.Entrada {
		t.Fatalf("aplicação/resgate: %+v / %+v", aplic, resg)
	}
	if boleto.Contraparte.Nome != "ALUGUEL SALA LTDA" || boleto.Tipo != "boleto" || boleto.Propria {
		t.Fatalf("boleto: %+v", boleto)
	}
	if qr.Contraparte.Nome != "MERCADO X" {
		t.Fatalf("qr code: %+v", qr)
	}

	// Janela: revisita 5 dias (dentro dos 7 da cota maior) e pede o histórico de uma vez.
	if sob, bloco := c.Janela(); sob > 6 || bloco < 366 {
		t.Fatalf("janela: %d %d", sob, bloco)
	}
}

func TestNomeNaDescricao(t *testing.T) {
	for desc, quer := range map[string]string{
		"Pix recebido Fulana de Tal":     "Fulana de Tal",
		"PIX ENVIADO BELTRANO":           "BELTRANO",
		"Pagamento de boleto EMPRESA SA": "EMPRESA SA",
		"Saída APLICACAO COFRINHOS":      "",
		"TARIFA PACOTE":                  "",
	} {
		if got := nomeNaDescricao(desc); got != quer {
			t.Errorf("%q: %q, queria %q", desc, got, quer)
		}
	}
}
