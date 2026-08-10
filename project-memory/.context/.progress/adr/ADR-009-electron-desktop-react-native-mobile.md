# ADR-009 — Electron Desktop + React Native Mobile

- **Status:** accepted (2026-08-09)
- **Contexto:** desktop e mobile na V1; Electron não roda em mobile.
- **Decisão:** desktop = Electron + React + TS + Vite + Tailwind + shadcn/ui (WebRTC nativo do
  Chromium; JanjaNode no main quando host). Mobile = React Native + Expo tooling + TS
  (development builds/native modules; react-native-webrtc; expo-secure-store; expo-sqlite
  SQLCipher). Tokens/semântica compartilhados via design-tokens; NÃO reutilizar componentes DOM.
- **Consequências:** duas implementações de UI (custo aceito); WebRTC/crypto exigem nativo no
  mobile (Expo Go não serve); nova arquitetura RN 0.76+ validada no iOS em device.
- **Spec:** `desktop-ui-ux-contract.md`, `mobile-ui-ux-contract.md`
- **Refs:** electronjs.org; reactnative.dev; docs.expo.dev
