# TASK-001 — Definicao congelada: Product → Specs → Architecture → Roadmap

> STATUS: done (2026-08-09). Todos os artefatos criados; aguardando approval do roadmap (M0).

## Routing stamp

- execution_mode: heavy-task (phase-roadmap, SEM implementacao)
- latest_user_request: "Bootstrap definitivo do JanjaCord — fechar Product, Specs, Architecture, UI/UX contract e Roadmap; nao escrever o produto ainda"
- workflow: core-configuracao-inicial-do-projeto (closeout) + product-criacao-de-projeto-novo (Phases 1-4)
- primary_owner: product-owner (lente residente; decisoes de produto ja congeladas pelo usuario)
- supporting_specialists:
  - development-solution-architect (arquitetura por camada, ADRs)
  - development-security-engineer (gate em identity, crypto, invites, transporte, host replication, TURN/relay)
  - design-ui-ux-designer (contratos UI/UX desktop + mobile)
  - development-selecao-de-arquitetura (validacao de candidatos por camada)
  - scouts (research tecnica: MLS, WebRTC RN/Electron, secure storage, replication/failover, push generico)
- required_gates: security review de decisoes crypto/identity (ADR-005 e afins); UI/UX contract antes de frontend; spec da primeira fatia operator-testable
- human_checkpoints: nenhum previsto (decisoes de produto estao LOCKED na definicao congelada; resolver tecnicamente via research)
- completion_gate: PRODUCT.md, ARCHITECTURE.md, CHECKLIST.md, INTEGRATIONS.md, specs/, adr/, master-plan.md, primeira wave de TASKs, status/current.md coerentes
- target_repo: workspaces/janjacord/janjacord/ (registrar apenas; NAO criar)
- external_tool_surface: nenhuma (sem MCP/ferramenta externa; docs oficiais via web)
- delegation_model: main-agent + scouts reais (research); lentes de especialista aplicadas no main agent para sintese
- context_quality: real (definicao congelada do usuario em 2026-08-09; memoria seed reclassificada de template->stale e substituida)
- evidence_required_before_done: arquivos .progress/.agentos/.operational listados no completion_gate
- stop_conditions:
  - NENHUM codigo de produto (apps/packages/infra)
  - NENHUM scaffold, package install, handler, database, UI mock, POC WebRTC ou crypto
  - NENHUM write em .setup/harnesses/agent-work-harness/
  - NAO mover itens V1 para V1.1 sem motivo/impacto/evidencia explicito

## Objetivo

Transformar a definicao congelada do JanjaCord (contrato 2026-08-09) em verdade duravel
executavel: PRODUCT.md, specs/, ADRs, ARCHITECTURE.md, INTEGRATIONS.md, CHECKLIST.md
phase-roadmap, master-plan e primeira wave de TASKs. Tornar o produto impossivel de ser
mal interpretado antes de qualquer implementacao.

## Fases desta operacao

1. Bootstrap closeout: router, project-state, task, reclassificacao de memoria.
2. Product framing: PRODUCT.md completo (sintese fiel da definicao congelada).
3. Spec-driven readiness: specs de produto (contract, read-once lifecycle, privacy).
4. Research tecnica (scouts paralelos): MLS, WebRTC RN/Electron, secure storage, host
   replication/failover, push generico, protocolo/rendezvous.
5. Architecture selection: ARCHITECTURE.md por camada + ADRs + INTEGRATIONS.md.
6. Specs tecnicas + UI/UX contracts (desktop/mobile).
7. Execution modeling: CHECKLIST.md phase-roadmap, master-plan, TASKs.
8. Status final + relatorio (sec 77 do contrato).

## Primeira task executavel futura (fora desta operacao)

TASK-002 (proposta): definir wire protocol v0 + crypto adapter boundary + janjanode
scaffold minimo — SOMENTE apos approval do roadmap e da spec da primeira fatia.
Fase 5 (implementation) nao inicia nesta operacao.

## Evidencia desta operacao

- `workspaces/janjacord/.memory/.context/.progress/PRODUCT.md`
- `workspaces/janjacord/.memory/.context/.progress/ARCHITECTURE.md`
- `workspaces/janjacord/.memory/.context/.progress/CHECKLIST.md`
- `workspaces/janjacord/.memory/.context/.progress/INTEGRATIONS.md`
- `workspaces/janjacord/.memory/.context/.progress/specs/*.md`
- `workspaces/janjacord/.memory/.context/.progress/adr/*.md`
- `workspaces/janjacord/.memory/.operational/plans/master-plan.md`
- `workspaces/janjacord/.memory/.context/.agentos/status/current.md`
