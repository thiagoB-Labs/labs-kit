package openfinance

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

// ComLimite envolve p com um limitador de requisições por processo (rps por processo).
func ComLimite(p Provedor, rps float64) Provedor {
	return &limitado{Provedor: p, l: rate.NewLimiter(rate.Limit(rps), max(1, int(rps)))}
}

type limitado struct {
	Provedor
	l *rate.Limiter
}

func (p *limitado) espera(ctx context.Context) error { return p.l.Wait(ctx) }

func (p *limitado) TrocarCodigo(ctx context.Context, code, verifier, redirect string) (Tokens, error) {
	if err := p.espera(ctx); err != nil {
		return Tokens{}, err
	}
	return p.Provedor.TrocarCodigo(ctx, code, verifier, redirect)
}

func (p *limitado) Renovar(ctx context.Context, t Tokens) (Tokens, error) {
	if err := p.espera(ctx); err != nil {
		return Tokens{}, err
	}
	return p.Provedor.Renovar(ctx, t)
}

func (p *limitado) Revogar(ctx context.Context, t Tokens) error {
	if err := p.espera(ctx); err != nil {
		return err
	}
	return p.Provedor.Revogar(ctx, t)
}

func (p *limitado) Contas(ctx context.Context, t Tokens) ([]Conta, error) {
	if err := p.espera(ctx); err != nil {
		return nil, err
	}
	return p.Provedor.Contas(ctx, t)
}

func (p *limitado) Transacoes(ctx context.Context, t Tokens, conta string, de, ate time.Time, cursor string) (Pagina, error) {
	if err := p.espera(ctx); err != nil {
		return Pagina{}, err
	}
	return p.Provedor.Transacoes(ctx, t, conta, de, ate, cursor)
}
