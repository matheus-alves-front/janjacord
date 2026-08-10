# JanjaCord — Research Brief (compartilhado com scouts)

## Produto em uma frase

JanjaCord e um comunicador privado de comunidades, invite-only, desktop + mobile, focado
exclusivamente em comunicacao: Server → Channel → Text/Voice/Video. Referencia filosofica:
Signal, nao Discord. Frase: "Server. Channel. Talk. Nothing else."

## Principios nao negociáveis

- Sem email, sem telefone. Cadastro = nickname + senha. Identidade pseudonima criptografica LOCAL.
- Conteudo E2EE; mensagens efemeras read-once (audience snapshot + purge apos consumo); sem historico permanente.
- Infraestrutura central JanjaCord MINIMA (bootstrap/rendezvous/STUN/TURN/update). Nada de storage de conteudo central.
- Servers sao user-hosted: desktop roda um "JanjaNode" (Node.js/NestJS) que hospeda o server localmente; replicas autorizadas para failover.
- Cliente assume CPU/memoria/storage/banda. WebRTC mesh P2P na V1 (voice ~10, video ~6 câmeras como guardrail inicial).
- Zero analytics, zero tracking SDK, zero telemetria comportamental.
- Sem "comunicacao impossivel de rastrear" como promessa: content-private, pseudonymous, metadata-minimizing.
- Nenhum protocolo criptografico proprio: padroes revisados + implementacoes maduras.
- Desktop: Electron + React + TypeScript + Vite + Tailwind + shadcn/ui. Mobile: React Native + Expo tooling + TS.
- Monorepo pnpm + Turborepo. Stack do host node: NestJS. Local data: SQLite encryptado. Zod, Zustand, TanStack Query, Vitest, Playwright.

## Arquitetura alvo (hipotese a validar)

- apps/: desktop, mobile, rendezvous, janjanode
- packages/: domain, protocol, crypto, networking, realtime, permissions, schemas, identity, persistence, design-tokens, testing
- infra/: rendezvous, stun, turn, docker, release
- docs/: protocol, threat-model, self-hosting

## Decisoes que a research deve suportar (NAO reabrir produto)

1. Melhor implementacao MLS / group-E2EE madura cross-platform (desktop Electron/TS + mobile RN).
2. Identity/device key hierarchy (sem derivar identidade de nickname+password; senha so protege vault local).
3. Secure vault desktop + mobile.
4. Multi-device linking (QR code) e revocation.
5. Host replication consistency + failover simples (primary + replicas autorizadas), split-brain, recovery.
6. Wire protocol versioning, ordering, replay protection.
7. WebRTC em Electron e React Native (PeerConnection, DataChannel, media); limitações mobile background.
8. STUN/TURN deployment e relay-only enforcement; self-hosted TURN.
9. Push generico opt-in sem conteudo ("New activity on JanjaCord"); trust boundary APNs/FCM.
10. Rendezvous minimo (bootstrap/discovery de hosts por ID, metadata efemera, sem conta central).

## Regras da pesquisa

- Usar docs oficiais/primarias primeiro (IETF RFC, docs de libs/repos oficiais, MDN, Electron, React Native, Expo).
- Nao basear decisao em blog aleatorio ou memoria de modelo. Registrar URLs concretas.
- Responder em PT-BR, objetivo, com: recomendacao, alternativas consideradas, trade-offs, riscos, URLs/fontes.
- NAO escrever codigo. NAO criar arquivos no repo de produto. Output = texto (a ferramenta entrega).
- Se um fato for incerto, marcar [INFERENCE] ou [UNVERIFIED] e dizer o que falta verificar.
