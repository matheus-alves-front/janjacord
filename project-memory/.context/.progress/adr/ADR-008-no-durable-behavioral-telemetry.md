# ADR-008 — No Durable Behavioral Telemetry

- **Status:** accepted (2026-08-09)
- **Contexto:** produto de privacidade não pode coletar comportamento; mas precisa ser operável.
- **Decisão:** zero user observability: nenhum SDK de analytics/tracking; sem logs de conteúdo;
  debugging local explícito/sanitizado/curto; crash report manual opt-in; sem durable read
  history; presence efêmera. Infra central: health agregado mínimo e documentado apenas se
  estritamente necessário para operar (sem correlação de identidade).
- **Consequências:** auditoria de dependências é gate de release; diagnóstico remoto difícil
  (aceito); operação da infra central usa métricas agregadas sem identidade de usuário.
- **Spec:** `privacy-metadata-and-telemetry-policy.md`
- **Refs:** contrato congelado §36, §52
