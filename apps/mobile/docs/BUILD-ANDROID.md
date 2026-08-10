# Build do JanjaCord Mobile (Android)

## Pré-requisitos

- **Android Studio** com SDK + **NDK** (SDK Manager → SDK Tools → NDK 27.x)
- **Rust** + **cargo-ndk**: `cargo install cargo-ndk`
- **Node ≥ 24** + pnpm (setup-windows.bat resolve no Windows)
- **Java 17+** (embutido no Android Studio)

## Build

```bash
# raiz do monorepo
pnpm install --no-frozen-lockfile
pnpm build

# mobile
cd apps/mobile
npx expo prebuild --platform android   # gera android/ + aplica o config plugin
npx expo run:android                   # builda o APK e instala no device/emulador
```

O `config plugin` (`plugins/withJanjacordCrypto.js`) injeta o módulo nativo
`janjacord-crypto`, e o `build.gradle` do módulo compila o crate Rust
(`packages/crypto-mobile`) com cargo-ndk para `arm64-v8a`, `armeabi-v7a`, `x86_64`.

## Testar com o desktop

1. No **desktop (Linux/Windows)**: crie o server → anote o convite `JC1-...`
2. No **celular**: o app → criar identidade → Host: `ws://<IP-do-desktop>:8931/signal`
   → colar o invite → conversar (E2EE real via MLS nativo)

> O celular e o desktop precisam estar na mesma rede (ou o desktop acessível).
> Firewall: liberar 8931/TCP no desktop.

## Problemas comuns

| Erro | Solução |
|---|---|
| `cargo: command not found` no build.gradle | instalar Rust e garantir `cargo` no PATH |
| `NDK not found` | instalar NDK 27+ no SDK Manager e setar `ANDROID_NDK_HOME` |
| `Expo Go` não tem o módulo | usar dev build (`expo run:android`) — Expo Go nunca terá o JanjacordCrypto |
| iOS | `npx expo prebuild --platform ios` + `expo run:ios` em macOS (Swift bindings gerados em `packages/crypto-mobile/bindings`) |
