# ADR-006 — WebRTC Mesh V1

- **Status:** accepted (2026-08-09) — research WebRtcScout
- **Contexto:** voz/vídeo em grupo na V1; objetivo econômico: custo central baixo, cliente
  assume banda/CPU.
- **Decisão:** mesh P2P full (N−1 PeerConnections por peer) na V1 — WebRTC nativo do Chromium
  no Electron; react-native-webrtc 124.x no mobile; node-datachannel no JanjaNode (host não
  participa de media). Guardrails iniciais: ~10 voz / ~6 câmeras (a medir com benchmarks reais;
  Simulcast p/ qualidade). SFU fora da V1 (SFrame avaliado pós-V1 com evidência).
- **Consequências:** escala limitada por construção (aceito); background mobile suspende fluxo
  (FGS/audio modes + spool cobrem offline); symmetric NAT exige TURN (RFC 8835 §3.4).
- **Spec:** `voice-video-webrtc.md`, `realtime-networking-protocol.md`
- **Refs:** RFC 8827/8831/8835; react-native-webrtc repo
