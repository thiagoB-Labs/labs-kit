// Package openfinance define o contrato com um provedor de Open Finance num modelo canônico: o
// adapter (openfinance/cumbuca) converte o formato do provedor e classifica os erros. Quem
// sincroniza só conhece esta interface. Extraído do psidalidi-fin (internal/provedor).
package openfinance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Provedor é um provedor de dados de Open Finance.
type Provedor interface {
	Nome() string
	// URLAutorizacao monta a URL para onde o navegador vai (OAuth com PKCE S256).
	URLAutorizacao(ctx context.Context, p PedidoAutorizacao) (string, error)
	TrocarCodigo(ctx context.Context, code, verifier, redirectURI string) (Tokens, error)
	Renovar(ctx context.Context, t Tokens) (Tokens, error)
	Revogar(ctx context.Context, t Tokens) error
	Contas(ctx context.Context, t Tokens) ([]Conta, error)
	// Transacoes devolve uma página de lançamentos de [de, ate] (dias inteiros, inclusive).
	// cursor vazio = primeira página; Pagina.Proximo vazio = última.
	Transacoes(ctx context.Context, t Tokens, contaExterna string, de, ate time.Time, cursor string) (Pagina, error)
}

// Janela é implementada pelo provedor que precisa de outra janela de sincronização (F3.4), em
// geral por causa de limites de requisição: dias revisitados a cada sincronização e tamanho
// máximo do bloco pedido de uma vez.
type Janela interface {
	Janela() (sobreposicaoDias, diasPorBloco int)
}

// PedidoAutorizacao são os parâmetros do authorize.
type PedidoAutorizacao struct {
	State         string
	CodeChallenge string
	RedirectURI   string
}

// Tokens são as credenciais OAuth. Nunca aparecem em log (LogValue).
type Tokens struct {
	Access        string    `json:"a"`
	Refresh       string    `json:"r,omitempty"`
	AccessExpira  time.Time `json:"ae"`
	RefreshExpira time.Time `json:"re,omitzero"`
}

// LogValue esconde os segredos.
func (t Tokens) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("accessExpira", t.AccessExpira), slog.Bool("temRefresh", t.Refresh != ""))
}

// String esconde os segredos.
func (t Tokens) String() string { return "provedor.Tokens{…}" }

// GoString esconde os segredos (%#v).
func (t Tokens) GoString() string { return t.String() }

// ExpiraEm diz se o access token expira antes de agora+margem.
func (t Tokens) ExpiraEm(agora time.Time, margem time.Duration) bool {
	return !t.AccessExpira.IsZero() && agora.Add(margem).After(t.AccessExpira)
}

// Conta é uma conta no modelo canônico.
type Conta struct {
	IDExterno     string
	Tipo          string // corrente | poupanca | pagamento | cartao | outra
	Nome          string
	Final         string
	Instituicao   string
	LogoURL       string
	TitularDoc    string // documento do titular, se informado (só vira HMAC)
	SaldoCentavos *int64
	SaldoEm       *time.Time
}

// Direcao de uma transação.
type Direcao string

// Direções.
const (
	Entrada Direcao = "entrada"
	Saida   Direcao = "saida"
)

// Tipos canônicos de transação (contracts/openapi.yaml, Tipo).
var Tipos = map[string]bool{
	"pix": true, "ted_doc": true, "boleto": true, "cartao": true, "debito_automatico": true,
	"tarifa": true, "saque": true, "deposito": true, "estorno": true, "rendimento": true, "outro": true,
}

// Transacao é um lançamento no modelo canônico. ValorCentavos é sempre positivo.
type Transacao struct {
	IDExterno     string // vazio se o provedor não dá id estável (F4.2)
	Data          time.Time
	DataHora      *time.Time
	ValorCentavos int64
	Direcao       Direcao
	Tipo          string
	Pendente      bool
	Descricao     string
	Contraparte   Contraparte
	// Propria marca dinheiro que só muda de lugar dentro do próprio titular (aplicação ou resgate
	// automático, como "cofrinhos"): entra como transferência interna (F5.1 c).
	Propria bool
}

// Contraparte é quem está do outro lado.
type Contraparte struct {
	Nome      string
	Documento string
	ChavePix  string
	ISPB      string
	Agencia   string
	Conta     string
}

// Pagina é uma página de transações.
type Pagina struct {
	Transacoes []Transacao
	Proximo    string
}

// Valida confere o que a sincronização assume de uma transação.
func (t Transacao) Valida() error {
	switch {
	case t.ValorCentavos <= 0:
		return fmt.Errorf("%w: valor não positivo", ErrResposta)
	case t.Direcao != Entrada && t.Direcao != Saida:
		return fmt.Errorf("%w: direção %q", ErrResposta, t.Direcao)
	case !Tipos[t.Tipo]:
		return fmt.Errorf("%w: tipo %q", ErrResposta, t.Tipo)
	case t.Data.IsZero():
		return fmt.Errorf("%w: sem data", ErrResposta)
	}
	return nil
}

// Erros classificados (F3.6).
var (
	// ErrConsentimento: token recusado, consentimento expirado ou revogado. Sem retentativa.
	ErrConsentimento = errors.New("provedor: consentimento inválido")
	// ErrTransitorio: rede, 5xx, timeout. Retentativa com backoff.
	ErrTransitorio = errors.New("provedor: falha transitória")
	// ErrResposta: resposta fora do formato. Sem retentativa.
	ErrResposta = errors.New("provedor: resposta inválida")
	// ErrNegado: o usuário negou a autorização.
	ErrNegado = errors.New("provedor: autorização negada")
)

// LimiteErr é o 429 do provedor.
type LimiteErr struct{ RetryAfter time.Duration }

func (e *LimiteErr) Error() string {
	return fmt.Sprintf("provedor: limite de requisições (retry após %s)", e.RetryAfter)
}

// ComoLimite devolve o LimiteErr, se for um.
func ComoLimite(err error) (*LimiteErr, bool) {
	var l *LimiteErr
	ok := errors.As(err, &l)
	return l, ok
}
