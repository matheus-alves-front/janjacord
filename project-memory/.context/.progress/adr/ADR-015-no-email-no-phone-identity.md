# ADR-015 — No-email / No-phone Identity Model (sem conta central)

- **Status:** accepted (2026-08-09)
- **Contexto:** recuperação tradicional (email/telefone) exigiria identidade verificável e
  backdoor central.
- **Decisão:** onboarding = nickname + senha; identidade criptográfica local; recovery key
  (mnemônico/export) exibida uma vez; perda de devices + recovery = perda da identidade
  (aceito). Sem password reset central, sem recuperação de private keys pelo operador,
  sem fingerprinting (ban por identidade criptográfica, não por IP/email/hardware).
- **Consequências:** UX de recuperação mais exigente (educação no onboarding); impossível
  suportar "esqueci minha senha" clássico; ban não impede nova identidade (reconhecido).
- **Spec:** `identity-local-vault-and-recovery.md`, `invite-membership-protocol.md`
- **Refs:** contrato congelado §9, §12, §44
