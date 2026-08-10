#!/usr/bin/env bash
# setup-machine.sh — prepara uma máquina para rodar o JanjaCord desktop.
# Uso: bash scripts/setup-machine.sh   (roda UMA vez em cada computador)
set -euo pipefail

echo "=== JanjaCord — preparação da máquina ==="

# 1. Node >= 24 (via nvm se ausente)
if ! command -v node >/dev/null 2>&1 || [ "$(node -e 'console.log(process.version.slice(1).split(".")[0])')" -lt 24 ]; then
  echo "[1/5] Node >= 24 ausente — instalando via nvm…"
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
  export NVM_DIR="$HOME/.nvm"
  [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
  nvm install 24
  nvm alias default 24
else
  echo "[1/5] Node OK: $(node --version)"
fi

# 2. pnpm
if ! command -v pnpm >/dev/null 2>&1; then
  echo "[2/5] pnpm ausente — instalando…"
  npm install -g pnpm@10
else
  echo "[2/5] pnpm OK: $(pnpm --version)"
fi

# 3. Rust + wasm32 (para compilar o MLS → WASM)
if ! command -v cargo >/dev/null 2>&1; then
  echo "[3/5] Rust ausente — instalando (rustup)…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
  . "$HOME/.cargo/env"
  rustup target add wasm32-unknown-unknown
else
  echo "[3/5] Rust OK: $(cargo --version)"
  rustup target list --installed | grep -q wasm32 || rustup target add wasm32-unknown-unknown
fi

# 4. wasm-pack
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "[4/5] wasm-pack ausente — instalando…"
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
else
  echo "[4/5] wasm-pack OK: $(wasm-pack --version)"
fi

# 5. Dependências + build do monorepo
echo "[5/5] instalando dependências e compilando (pode demorar alguns minutos)…"
export PATH="$HOME/.cargo/bin:$PATH"
pnpm install --no-frozen-lockfile
pnpm build

echo ""
echo "=== PREPARAÇÃO CONCLUÍDA ==="
echo "Para rodar o app:  cd apps/desktop && node_modules/.bin/electron . --no-sandbox"
