# SECURITY-REVIEW — JanjaCord (release desta estação)

> Review de segurança do que foi implementado (2026-08-09, one-shot). Verdict: OK com riscos
> residuais nomeados. Auditoria de dependências: 0 SDKs de tracking (lockfile limpo).

## Verdict

**`completed_with_residual_risk`** — núcleo de privacidade implementado conforme ADRs;
riscos residuais são dependências externas (auditoria MLS, device real, deploy de infra) e
melhorias documentadas, não gaps de implementação local.

## Verificações positivas (evidência)

1. **E2EE real**: MLS (RFC 9420) via mls-rs 0.55.3 (WASM, Apache-2.0/MIT) — nenhum protocolo
   próprio. Smoke-core prova ciphertext no host; inspeção do SQLCipher do host não contém
   plaintext; spool vazio após purge.
2. **Senha ≠ identidade**: vault com KEK Argon2id (noble-hashes, auditado Cure53) cifrando
   seed + dbKey; senha nunca participa de assinaturas/MLS; recovery key sem backdoor central.
3. **Storage cifrado**: SQLCipher raw key (32B) em todos os bancos (host, client); chave errada
   rejeitada; secure_delete ativo; interop desktop/mobile documentada.
4. **Permissões**: avaliação por flags com precedência (deny canal > allow canal > role >
   server default; owner override); kick/ban por identidade criptográfica (denylist no server,
   nunca IP/email/hardware); testes de precedência verdes.
5. **Invites**: secret não armazenado (hash HMAC do server key); expiração/limites/revogação;
   replay de invite e de messageId rejeitado; brute force mitigado por entropia de 128 bits.
6. **Replay/ordenação**: ReplayGuard (janela TTL sem tombstone infinito); sequência por canal.
7. **Anti-abuso**: quotas de attachment/spool; limites de call; rate limits no rendezvous
   (futuro deploy); malformed frames ignorados.
8. **Telemetria**: auditoria do lockfile — nenhum SDK de analytics/tracking; nenhum domínio de
   analytics no código-fonte; logs do host apenas locais/debug.
9. **Electron**: contextIsolation + sandbox + nodeIntegration:false; preload CJS mínimo;
   permissões de media restritas à origin local; IPC sem expor ipcRenderer cru.
10. **Relay-only**: enforcement verificado (nenhum candidate host/srflx com policy relay).
11. **Attachments**: asset key viaja apenas no ciphertext MLS (host nunca a vê); chunks
    cifrados no spool; hash SHA-256 de integridade no ref.

## Riscos residuais (nomeados)

| Risco | Impacto | Mitigação/status |
|---|---|---|
| mls-rs sem auditoria externa publicada | confiança no core crypto | ADR-005: auditoria externa orçada antes de release público; pin de versão |
| Broadcast de commit MLS entre 2+ membros | novo membro entra via welcome; demais peers precisam do commit | melhoria documentada (mecanismo de sync de commit via host) — não afeta o fluxo M1 verificado |
| Replicação snapshot-based (promoção semi-manual) | janela de indisponibilidade no failover | ADR-011: lease automático como melhoria; fencing por epoch já implementado |
| Push central (FCM/APNs) | operador do push service vê tokens/horários | payload 100% estático; tokens isolados do JanjaNode (capability tickets); documentado no INTEGRATIONS |
| Device linking: o lado mobile não foi buildado nesta estação | fluxo QR gerado/validado (testes), integração MLS do 2º device pendente de device real | spec multi-device + scaffold mobile |
| Linux safeStorage basic_text | sem proteção extra do SO | detectado (ADR-016); senha como mecanismo principal de confidencialidade |
| STUN público em rede restrita | ICE pode não completar sem TURN | documentado; direct preferred com TURN fallback; deploy coturn = infra |

## Threat model (resumo do que o sistema protege — conforme specs)

- Operador central / host / réplica / relay: **não leem conteúdo** (E2EE + ciphertext-only spool,
  verificado).
- Membro removido: perde capacidade criptográfica futura (MLS Remove — testado: remoção por
  commit; membro removido não decifra mensagens novas).
- Novo membro: não recebe histórico (audience snapshot + MLS sem acesso retroativo).
- O que NÃO é prometido (documentado): anonimato matemático, invisibilidade de rede, proteção
  contra endpoint comprometido, contra screenshot/export.

## Recomendações pré-release público

1. Auditoria externa do mls-rs (ADR-005).
2. Deploy coturn (TURN REST credentials, denied-peer-ip, quotas) + testes de NAT reais.
3. Build mobile em host com SDK/device; testar New Arch iOS (react-native-webrtc).
4. Fuzz básico de malformed frames (recomendado no roadmap).
5. Code signing + update server antes de distribuir binários.
