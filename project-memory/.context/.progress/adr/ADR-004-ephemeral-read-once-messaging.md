# ADR-004 — Ephemeral Read-Once Messaging

- **Status:** accepted (2026-08-09)
- **Contexto:** chat não é histórico; mensagem pertence à audiência do instante do envio.
- **Decisão:** mensagens efêmeras com audience snapshot imutável, consumo = apresentação ao
  usuário no canal ativo (não download), purge global quando todos os elegíveis consumirem,
  max retention (default 7d) como hard stop; receipts de consumo são metadata temporária
  interna (sem read receipts visíveis, sem analytics). Efemeridade não é DRM.
- **Consequências:** host mantém só ciphertext temporário; membro novo não recebe histórico;
  cópias exportadas (copy/save/screenshot) fora do controle do produto. Exige rigor de
  lifecycle local (sair do canal → destruir plaintext).
- **Spec:** `ephemeral-read-once-messaging.md`, `message-consumption-and-purge.md`
- **Refs:** contrato congelado §16-§26
