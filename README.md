# JanjaCord

**Server. Channel. Talk. Nothing else.**

JanjaCord é um comunicador privado, invite-only e self-hosted para comunidades. A identidade é
criada localmente, o conteúdo é criptografado de ponta a ponta e cada comunidade pode ser mantida
pelos computadores dos próprios membros.

O desktop é a superfície principal atual. Ele inicia o host da comunidade, cria ou aceita um
convite `JC3`, tenta conexão direta e usa um JanjaBridge comunitário quando a rede exige
rendezvous, signaling ou TURN.

> **Estado do projeto:** candidato desktop R9 validado localmente no Linux. Ainda não é uma
> release pública final: instalação e autostart em Windows real, login/reboot em sistemas reais e
> o aceite WAN entre duas redes físicas continuam pendentes. Mobile está em uma fase posterior.

## O que funciona hoje

- identidade pseudônima local com nickname, senha, vault cifrado e recovery key;
- criação de comunidade com JanjaNode embutido no desktop do Owner;
- entrada por um único convite `JC3`, sem conta central ou URL de host no fluxo comum;
- mensagens de grupo E2EE com MLS, audience snapshot e purge por consumo ou retenção;
- anexos cifrados, com o host armazenando apenas bytes cifrados e temporários;
- canais, presença, roles, permissões, overrides, invites, kick e ban;
- voz e vídeo em WebRTC mesh P2P, com modos direct-first e relay-only;
- Community Hosts autorizados para replicação, revogação e failover;
- múltiplos JanjaBridges por comunidade, sem bridge global obrigatório da JanjaCord;
- AppImage e DEB com fluxo de empacotamento e validação reproduzível;
- zero SDK de analytics e zero telemetria comportamental.

## Como funciona

```text
                         Internet
                            |
                 +----------+----------+
                 |                     |
          JanjaBridge A         JanjaBridge B
       rendezvous / TURN      rendezvous / TURN
                 |                     |
                 +----------+----------+
                            |
              signaling e conectividade efêmeros
                            |
        +-------------------+-------------------+
        |                                       |
 Desktop do Owner                         Desktop de membro
 Primary Host + cliente   <--- E2EE --->        cliente
        |
        +---- snapshot cifrado ---- Community Host autorizado
                                      Replica / standby
```

### Primary Host e Community Hosts

Quem cria a comunidade começa como Owner e Primary Host. Um membro com autorização pode aceitar
um grant vinculado ao próprio device e manter uma réplica cifrada. Hosting é uma capability
separada: não promove o membro para Admin e não concede acesso adicional ao conteúdo.

Uma promoção automática exige grant com a capability `promote`, epoch/fencing e maioria estrita
de pelo menos dois JanjaBridges independentes confirmando a ausência do Primary. Sem quorum, a
réplica permanece read-only para evitar duas autoridades de escrita.

### JanjaBridge

JanjaBridge é infraestrutura auxiliar self-hostable e auditável. Ele fornece:

- descoberta de hosts por records assinados e com TTL;
- signaling ICE efêmero;
- emissão de credenciais TURN de curta duração;
- coturn para redes que não permitem conexão direta.

O bridge não hospeda a comunidade e não recebe mensagens, anexos, voz, vídeo ou identidade local.
Como qualquer relay de rede, ele ainda pode observar metadados de transporte, como IP, horário e
volume. Uma comunidade pode configurar vários bridges e não depende de infraestrutura operada pela
JanjaCord.

## Privacidade e limites

1. Não existe cadastro central por email ou telefone.
2. Comunidades não são públicas e só podem ser acessadas por convite.
3. Mensagens e anexos são cifrados antes de sair do cliente.
4. O host mantém estado durável cifrado e conteúdo pendente cifrado com TTL.
5. Read-once controla as cópias mantidas pelo JanjaCord; não impede screenshot, gravação ou cópia
   externa feita por um participante autorizado.
6. Direct-first pode revelar IPs entre peers. Relay-only reduz essa exposição ao custo de
   concentrar metadata no operador TURN.
7. O projeto promete privacidade de conteúdo e minimização de metadata, não anonimato absoluto.
8. Não há recovery central: perder a identidade e a recovery key significa perder o acesso.

## Componentes

| Caminho | Responsabilidade |
|---|---|
| `apps/desktop` | Electron + React: identidade, comunidades, conversa, calls, hosts e conectividade |
| `apps/janjanode` | Membership, spool cifrado, signaling, grants, snapshots, réplica e failover |
| `apps/rendezvous` | Control plane efêmero do JanjaBridge, records assinados e credenciais TURN |
| `apps/push` | Base de push genérico; provider real FCM/APNs ainda não faz parte do desktop atual |
| `apps/mobile` | Cliente React Native/Expo em fase posterior; não faz parte da validação desktop R9 |
| `packages/crypto-core` | MLS com `mls-rs` compilado para WASM |
| `packages/crypto` | KDF, AEAD, assinatura e boundaries criptográficos compartilhados |
| `packages/identity` | Identidade local, vault e recovery |
| `packages/networking` | WebSocket local, WebRTC DataChannel, ICE, TURN, reconnect e bridge failover |
| `packages/persistence` | Persistência SQLite/SQLCipher |
| `packages/protocol` | Envelopes, attachments e contratos de conectividade |
| `packages/permissions` | Roles, permission flags e precedência de overrides |
| `packages/schemas` | Validação Zod de comandos e wire protocol |
| `infra/docker` | Bundle self-hosted de JanjaBridge com Nginx, rendezvous, coturn e Certbot |

O monorepo usa pnpm, Turborepo e TypeScript. O desktop usa Electron, React e Vite; o JanjaNode usa
NestJS e `node-datachannel`; a criptografia de grupo usa `mls-rs` via WASM.

## Executar localmente

### Requisitos

- Node.js `>= 22.12.0`;
- pnpm `10.25.0` via Corepack ou instalação equivalente;
- toolchain nativa compatível com Electron para instalar dependências nativas;
- Rust e `wasm-pack` somente para recompilar o MLS com `JC_REBUILD_WASM=1`.

### Instalação

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm build
```

### Abrir o desktop

```bash
pnpm --filter @janjacord/desktop start
```

Na primeira abertura:

1. crie nickname e senha;
2. guarde a recovery key;
3. crie uma comunidade ou escolha `Adicionar servidor`;
4. para entrar em outra comunidade, cole o convite `JC3` no campo único.

Para abrir um segundo perfil no mesmo computador:

```bash
JC_USERDATA_DIR=/tmp/janjacord-member \
  pnpm --filter @janjacord/desktop start
```

O segundo perfil usa outro vault e outro banco local. Remova o diretório temporário depois do
teste se não quiser preservar essa identidade.

## Desenvolvimento e testes

Comandos gerais do monorepo:

```bash
pnpm typecheck
pnpm test
pnpm build
```

Validações específicas da fase desktop:

```bash
pnpm --filter @janjacord/desktop run smoke:connectivity
pnpm --filter @janjacord/desktop run smoke:replication
pnpm --filter @janjacord/desktop run smoke:operator-ipc
pnpm --filter @janjacord/desktop run validate:release-config
```

Os smokes cobrem conexão direta, TURN, relay-only, failover de bridge, grants, snapshot,
replicação, promoção, self-fencing e os IPCs usados pelo fluxo operador.

O candidato R9 passou localmente:

- 178 testes;
- typecheck e build de todo o workspace;
- smokes de E2EE, purge, calls, conectividade, TURN, replicação e operador;
- 22 estados visuais do AppImage;
- 10 checks do fluxo operador empacotado;
- instalação, execução e remoção do DEB em Debian Bookworm limpo.

Esses resultados não substituem o aceite físico ainda pendente em Windows e WAN.

## Empacotamento desktop

Valide a configuração antes de gerar qualquer artefato:

```bash
pnpm --filter @janjacord/desktop run validate:release-config
```

Linux, depois de congelar e revisar a fonte:

```bash
JANJACORD_SOURCE_FROZEN=1 \
  pnpm --filter @janjacord/desktop run dist:linux
```

Windows possui caminhos separados para instalador NSIS de teste sem assinatura e release
assinada:

```powershell
pnpm --filter @janjacord/desktop run dist:win:test
pnpm --filter @janjacord/desktop run dist:win:release
```

O segundo comando exige configuração real de assinatura. Não publique o artefato unsigned como
release. Política de proveniência, autostart, firewall, assinatura e validação completa:
[docs/DESKTOP-RELEASE.md](docs/DESKTOP-RELEASE.md).

## Hospedar um JanjaBridge

O operador precisa de um host Linux público, Docker Compose v2, dois hostnames DNS apontando para
o mesmo IPv4 e portas de TURN/ACME liberadas. A partir de `infra/docker`:

```bash
./scripts/init.sh bridge.example.com ops@example.com 203.0.113.10 turn.bridge.example.com
docker compose config --quiet
docker compose up -d --build
./scripts/issue-certificate.sh
docker compose ps
```

O primeiro certificado é apenas bootstrap. Não distribua o pairing antes de
`issue-certificate.sh` concluir com um certificado ACME válido. O guia de DNS, portas, secrets,
backup, update, rollback e diagnóstico está em
[infra/docker/README.md](infra/docker/README.md).

## Estado do roadmap

### Validado localmente

- desktop Linux operável e empacotado;
- setup sem host URL ou variável de ambiente no caminho comum;
- convite JC3, JanjaBridge, conexão direct/TURN e multi-bridge;
- Community Hosts, revogação, replicação, quorum e fencing;
- mensagens, anexos e calls preservando os boundaries de privacidade;
- reviews independentes de código, segurança, QA/release e UI/UX.

### Pendente antes da release desktop

- instalar, remover, assinar e executar o NSIS em Windows real;
- validar autostart e cleanup após login/reboot em Windows e Linux reais;
- executar o fluxo completo em dois desktops e duas redes físicas;
- operar dois Community Hosts e dois JanjaBridges públicos;
- validar texto, anexo, áudio/vídeo e falhas reais de Primary e bridge com pessoas;
- produzir SBOM e concluir auditoria externa dos componentes criptográficos antes de distribuição
  ampla.

### Fora do escopo desktop atual

- mobile Android/iOS, device linking e push FCM/APNs real;
- SFU, screen share, bots, plugins, DMs, descoberta pública e histórico permanente.

## Segurança

O Electron mantém `contextIsolation`, renderer sem Node e preload restrito. Entradas IPC, wire
protocol, signaling WebRTC, host records e grants são validados antes de chegar aos runtimes
nativos. WebSockets externos têm limite de payload, compressão desativada e timeout de handshake.
TURN usa credenciais temporárias; o shared secret permanece no JanjaBridge.

O modelo de segurança não considera host ou bridge confiável para confidencialidade do conteúdo.
Eles ainda podem causar indisponibilidade, atrasar tráfego e observar a metadata necessária para
operar a rede.

## Licença

Ainda não há um arquivo `LICENSE` neste repositório. O objetivo do projeto é ser open source, mas
os termos de uso, cópia, modificação e redistribuição precisam ser definidos antes de uma release
pública. Até isso acontecer, a disponibilidade do código não deve ser interpretada como concessão
automática de uma licença open source.
