# labs-kit

Módulo Go com clientes genéricos reaproveitados pelos serviços da thiagoB-Labs. Sem regra de
negócio, sem segredo, sem estado: cada serviço guarda os próprios tokens e decide o que mostrar.

| Pacote | Para quê | Origem |
| --- | --- | --- |
| `webpush` | Web Push com VAPID (RFC 8291/8292), lista fechada de serviços de push (sem SSRF) | psidalidi-bem-estar |
| `gcal` | Google Agenda: OAuth PKCE, agenda do app (`calendar.app.created`), eventos, livre/ocupado | psidalidi-api |
| `openfinance` | Modelo canônico de contas e transações de Open Finance e erros classificados | psidalidi-fin |
| `openfinance/cumbuca` | Adapter do Open Finance Data MCP da Cumbuca (OAuth + registro dinâmico + MCP) | psidalidi-fin |
| `cofre` | AES-256-GCM com rotação de chave (`id:base64,...`) e HMAC de identificadores | psidalidi-fin |
| `pkce` | Verifier/challenge S256 e valores aleatórios para state | — |
| `telefone` | E.164, 9º dígito do celular brasileiro, máscara para exibição | psidalidi-api |

```sh
go get github.com/thiagoB-Labs/labs-kit@latest
```

Versões seguem SemVer por tag (`v0.x`: a API ainda pode mudar entre minors). Mudança que quebra
chamador sobe a minor e vai descrita no corpo do commit.

## Desenvolvimento

```sh
go vet ./... && go test -race ./...
```
