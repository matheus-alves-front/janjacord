# Build do JanjaCord Mobile (Android)

O app móvel roda o **MLS/E2EE real** via crate Rust compilado com UniFFI
(`packages/crypto-mobile` → `libjanjacord_mobile.so` por ABI), sem WASM.

## Pré-requisitos

- **JDK 17** (Temurin) — o Gradle 8.14 do Expo **não roda em JDK 21+/25**
  - Linux: `~/jdk17` (ou `org.gradle.java.home` no `android/gradle.properties`)
- **Android SDK + NDK 27.x** (`ANDROID_HOME` apontando pro SDK)
  - `platform-tools`, `platforms;android-35`, `build-tools;35.0.0`, `ndk;27.0.12077973`
- **Rust (rustup)** + targets Android:
  ```bash
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  cargo install cargo-ndk
  ```

## Build

```bash
# raiz do monorepo
pnpm install --no-frozen-lockfile
pnpm build

# mobile — gera o projeto android/ (prebuild)
cd apps/mobile
npx expo prebuild --platform android

# builda o APK (compila o Rust via cargo-ndk no módulo nativo)
cd android
ANDROID_HOME=$HOME/Android/Sdk JAVA_HOME=$HOME/jdk17 \
  ./gradlew assembleDebug -PreactNativeArchitectures=arm64-v8a
# → app/build/outputs/apk/debug/app-debug.apk
```

> `arm64-v8a` cobre celulares modernos. Para todas as ABIs, remova o `-P`.
> No Windows use `gradlew.bat` e `JAVA_HOME` do Android Studio (JDK 17).

## Instalar no celular

```bash
# USB (depuração ativada) ou emulador
adb install app/build/outputs/apk/debug/app-debug.apk
# ou copie o APK pro celular e toque nele (instalação manual)
```

> O app é **dev client** (não Expo Go) — o módulo nativo só existe no build.
> Para o app abrir com JS de desenvolvimento, rode o Metro:
> `npx expo start` e abra o app no mesmo Wi-Fi (dev launcher).
> Para APK standalone sem Metro: `./gradlew assembleRelease` + bundling.

## Testar com o desktop (host)

1. **Desktop (Linux/Windows)**: abra o app, crie identidade → "Criar server" → `+ invite` → copie o `JC1-...`
2. **Celular**: crie identidade → Host `ws://<IP-do-desktop>:8931/signal` → cole o invite → converse
   - E2EE real: cifra no celular (MLS nativo), decifra no desktop — o host só vê ciphertext
   - Celular e desktop na mesma rede (ou Tailscale); libere **8931/TCP** no desktop

## Problemas comuns

| Erro | Solução |
|---|---|
| `Could not start 'cargo'` | Instalar Rust + `cargo-ndk`; o módulo acha `~/.cargo/bin/cargo` automaticamente |
| `could not compile ... note: rustup target install aarch64-linux-android` | `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` |
| `Unsupported class file major version` / Gradle falha com Java 25 | Usar **JDK 17** (`org.gradle.java.home` no `android/gradle.properties`) |
| `PackageList.java: cannot find symbol JanjacordCryptoPackage` | Re-rodar `npx expo prebuild` (o autolinking registra o módulo `modules/janjacord-crypto`) |
| Expo Go não tem o módulo | Usar dev build — Expo Go nunca terá o JanjacordCrypto |
| iOS | macOS + `npx expo prebuild --platform ios`; bindings Swift em `packages/crypto-mobile/bindings` |

## Arquitetura do módulo nativo

- `modules/janjacord-crypto/android/` — módulo RN (Kotlin) registrado pelo **autolinking** (não precisa de config plugin)
- `modules/janjacord-crypto/android/build.gradle` — `preBuild` → `cargo ndk ... build --release` (task `cargoNdkBuild`)
- `packages/crypto-mobile/` — crate UniFFI (bindings Kotlin/Swift/Python gerados em `bindings/`)
- O JS acessa via `NativeModules.JanjacordCrypto` (wrapper em `apps/mobile/src/crypto.ts`)
