# JanjaBridge self-hosted

Para um caminho guiado do zero até o pairing no desktop, veja
[`docs/tutorial-janjabridge-server.md`](../../docs/tutorial-janjabridge-server.md). Este arquivo
continua sendo a referência detalhada de operação, backup, update, rollback e diagnóstico.

Este diretório entrega o plano de dados público mínimo do JanjaBridge: rendezvous/signaling do
repo, coturn com credenciais REST, Nginx para HTTPS/WSS e Certbot para certificado público. O
rendezvous persiste somente revogações e high-water marks necessários para impedir replay,
downgrade e retorno de grants revogados após restart; records e signaling continuam efêmeros. O TURN mantém allocations somente
em memória. Nenhum volume recebe mensagens, anexos, mídia ou identidade da comunidade.

O bundle não inclui `apps/push`: a implementação atual ainda despacha apenas o provider `mock` e
não é um push FCM/APNs utilizável. Um profile de push só deve ser adicionado quando houver um
dispatcher real e credenciais operáveis.

## Pré-requisitos

- host Linux público com Docker Engine e Docker Compose v2;
- dois hostnames DNS A no mesmo IPv4 público: um para HTTPS/WSS (`bridge.example.com`) e outro
  exclusivo para TURN (`turn.bridge.example.com`); não use proxy/CDN no hostname TURN;
- Node.js 22+ e OpenSSL no host para a inicialização;
- relógio do host sincronizado por NTP;
- executar `init.sh` e Compose com o mesmo usuário não-root; a inicialização grava o UID/GID do
  operador em `.env`, para que o processo Node leia secrets `0600` sem torná-los públicos;
- firewall e NAT com mapeamento 1:1 para:
  - `80/tcp`: desafio ACME e redirect HTTPS;
  - `443/tcp`: HTTPS/WSS e TURN/TLS, separados por SNI;
  - `3478/udp` e `3478/tcp`: STUN/TURN;
  - `49160-49259/udp`: allocations relay (100 portas por padrão).

A faixa estreita é intencional para um operador comunitário pequeno. Aumente
`TURN_MIN_PORT`/`TURN_MAX_PORT` e o firewall juntos se a ocupação justificar. Não publique portas
administrativas do Docker ou do coturn.

## Inicialização

Execute a partir de `infra/docker`:

```bash
./scripts/init.sh bridge.example.com ops@example.com 203.0.113.10 turn.bridge.example.com
docker compose config --quiet
docker compose up -d --build
./scripts/issue-certificate.sh
docker compose ps
```

O primeiro `up` usa um certificado bootstrap autoassinado de sete dias apenas para permitir que o
Nginx sirva o webroot ACME. Não distribua o pairing enquanto `issue-certificate.sh` não terminar.
O script de certificado usa ACME HTTP-01; a porta 80 precisa chegar diretamente ao Nginx.

### Por que existem dois hostnames na mesma porta 443

O container `gateway` faz multiplexação TCP com `ssl_preread`: ClientHello com SNI
`bridge.example.com` segue para o terminador HTTPS/WSS interno; SNI `turn.bridge.example.com`
segue sem terminar TLS para o coturn. Hostname desconhecido ou cliente TLS sem SNI falha fechado.
O certificado ACME contém os dois SANs. Isso permite TURN/TLS em 443 com um único IPv4 sem fazer
o Nginx interpretar TURN como HTTP e sem expor a porta TLS interna 5349 no host.

Esse desenho depende de o cliente TURN enviar SNI. A versão pinada do coturn/`turnutils_uclient`
usada no diagnóstico envia SNI; o gate final continua sendo o cliente JanjaCord real na rede
restritiva que se pretende suportar. ECH, proxy/CDN no registro TURN e NAT sem hairpin podem mudar
o comportamento e não são cobertos pelo smoke local.

`init.sh` recusa sobrescrever uma instalação existente. Ele cria secrets com modo `0600`, um
descriptor público e um pairing JSON privado:

- `state/bridge-descriptor.json`: pode ser publicado/distribuído;
- `state/bridge-pairing.json`: contém um pairing token com TTL de 24h, one-shot, e deve ser
  compartilhado uma vez por canal confiável;
- `secrets/turn-shared-secret`: somente coturn e o issuer de credenciais;
- `secrets/bridge-pairing-admin-key`: somente o control plane; nunca é compartilhado;
- `secrets/bridge-signing-key.pem`: assina o descriptor e precisa de backup/rotação controlada.

O descriptor segue o contrato assinado `SignedBridgeDescriptor` de S1 e expira em 365 dias. O
shared secret REST do TURN nunca entra nos JSONs de descriptor/pairing. Clientes devem receber
username/password temporários emitidos pelo control plane, nunca esse shared secret.

O desktop guarda o documento privado de pairing no trust store local autenticado, mas passa ao
JanjaNode duas listas separadas: `JC_BRIDGE_DESCRIPTORS=[SignedBridgeDescriptor]` e
`JC_BRIDGE_PAIRINGS=[{bridgeId,pairingToken}]`. O token não entra no descriptor, JC3, signed host
record, logs ou enrollment de réplica. Somente o primeiro `access.issue` de uma comunidade ainda
desconhecida leva o token pelo WSS privado. O bridge valida o MAC com o admin key, persiste o
consumo antes de emitir credencial e vincula o token à primeira authority/server/host. Replay,
inclusive após restart/compactação, falha. Reinícios e hosts posteriores usam grants assinados da
mesma comunidade para obter access tokens curtos, sujeitos à quota por comunidade; o admin key
nunca sai do bridge. Para mintar outro documento sem expor esse key:

```bash
./scripts/mint-pairing.sh 24
```

## Contratos backend para IPC/UI

Todos os comandos abaixo viajam no frame autenticado `{event:"command",data:<command>}` e retornam
`{event:"result",data:{ok:true,data:...}}` ou `{ok:false,error:{code,message}}`.

- `host.candidate.register`: `{type:"host.candidate.register",hostPublicKey,enrollmentPublicKey,hostId,deviceProof:{proofId,issuedAt,signature},hostProof:{proofId,issuedAt,signature}}`. O membro assina o mesmo binding
  `{serverId,subjectIdentityId,subjectAuthPublicKey,hostPublicKey,enrollmentPublicKey,hostId,proofId,issuedAt}`
  uma vez com a identity/device key e uma vez com a host signing key. Retorna
  `{candidate:{candidateId,subjectIdentityId,nickname,subjectAuthPublicKey,hostPublicKey,enrollmentPublicKey,hostId,status,createdAt,expiresAt}}`.
- `host.grant.create`: `{type:"host.grant.create",subjectIdentityId,candidateId,capabilities,expiresInMs?}`.
  O owner nunca fornece chaves; o backend resolve a candidatura persistida. Retorna
  `{grant:{payload,publicKey,signature},candidateId}`.
- `host.grant.accept`: `{type:"host.grant.accept",grantId,hostProof:{proofId,issuedAt,signature}}`; retorna `{grantId,accepted:true}`.
- `host.grant.list`: `{type:"host.grant.list"}`; somente `manage_hosts`; retorna
  `{grants:[{grantId,subjectIdentityId,subjectAuthPublicKey,hostPublicKey,enrollmentPublicKey,hostId,status,capabilities,expiresAt,createdAt,acceptedAt,revokedAt,grant,revocation}],candidates:[...],eligibleHostDevices:[...]}`.
- `host.grant.revoke`: `{type:"host.grant.revoke",grantId,reason?}`; retorna `{revocation:{payload,publicKey,signature}}`.
- `replica.enroll`: `{type:"replica.enroll",grantId,hostProof:{proofId,issuedAt,signature}}`; retorna exclusivamente
  `{sealedEnrollment:{version:2,algorithm:"X25519-HKDF-SHA256-AES-256-GCM",transcript:{payload:{version:1,enrollmentId,recipientPublicKey,serverId,authorityFingerprint,grantId,generation,subjectAuthPublicKey,replicaHost,primaryHost,snapshotHash,epoch,seq,issuedAt,expiresAt,bridgeSetHash},publicKey,signature},ephemeralPublicKey,nonce,ciphertext,tag}}`.
  O transcript público assinado e o AAD vinculam todo o contexto; DB key, snapshot SQLCipher, grant
  completo e descriptors ficam no ciphertext. Pairing de operador nunca entra no enrollment e nada
  disso aparece em `server.state`/`host.grant.list`.
- `replica.snapshot`: `{type,grantId,serverId}`; retorna
  `{dbB64,serverId,authorityPublicKey,epoch,seq}` somente a sessão/grant `replicate` ativo.
- `replica.ping`: `{type,grantId,serverId,epoch}`; retorna
  `{ok:true,data:{serverId,epoch,syncMode:"encrypted-snapshot",twoSafe:false}}` apenas quando todos
  os campos de fence conferem.
- `replica.promote` não existe no `HostCommand`/IPC. Promoção só ocorre internamente após witness
  live vinculado ao primary conhecido, grant `promote` ativo e quorum estrito.
- `connectivity.iceConfig`: `{type:"connectivity.iceConfig"}`; retorna browser-compatible
  `{iceServers:[{urls,username,credential,credentialType:"password"}],iceTransportPolicy:"all"|"relay",expiresAt}`.
- `invite.list`: `{type:"invite.list"}`; exige `manage_invites`; retorna
  `[{inviteId,initialRoleId,maxUses,used,expiresAt,createdAt,status:"active"|"revoked"|"expired"|"exhausted"}]`, nunca o secret.

`server.state` sempre inclui `hostCandidates` e `hostGrants`: `manage_hosts` vê todos; membro comum
vê somente os próprios. Cada item tem `status: "pending"|"accepted"|"revoked"|"expired"` estável.
`eligibleHostDevices` é exclusivo de `manage_hosts`. Nenhum desses estados contém enrollment ou DB key.

O signed host record é único por renewal e anuncia todos os endpoints `/signaling` configurados.
Os mesmos bytes/requestId são enviados a até três bridges; o primeiro ACK válido comita seq/hash e
ACKs tardios do mesmo hash são idempotentes. O renewal seguinte encadeia no mesmo hash em todos.

Após o grace de lease, uma réplica pede witness live a todos os bridges pareados. Cada bridge apenas
informa se existe socket autenticado para o binding do primary; ele não decide membership. Promoção
automática exige grant local `promote` ativo, no mínimo dois bridges independentes configurados e
maioria estrita dizendo primary ausente no mesmo window: 2/2 ou 2/3. Zero/um bridge, qualquer
resposta “online”, falta de quorum, bridge indisponível ou grant
revogado mantém a réplica read-only. Esse desenho troca disponibilidade por proteção contra
split-brain: com dois bridges, a queda de um bloqueia promoção automática.

No IPC desktop, a primeira conexão JC2 sem pin retorna
`{ok:false,error:{code:"legacy_confirmation_required",fingerprint,data:{serverId,hostPublicKey,fingerprint,confirmationToken,expiresAt}}}`.
A segunda chamada deve reapresentar exatamente token, chave e fingerprint dentro do TTL; só então
o pin TOFU é persistido. Mudança de qualquer campo, expiração ou ausência do desafio falha fechado.

## Imagem do rendezvous

Por padrão, Compose constrói `apps/rendezvous` com `rendezvous.Dockerfile`. Para usar uma imagem
publicada compatível, configure uma referência imutável em `.env` e faça pull antes do rollout:

```dotenv
JANJABRIDGE_IMAGE=registry.example.com/janjacord/rendezvous@sha256:...
```

```bash
docker compose pull rendezvous
docker compose up -d --no-build rendezvous gateway
```

Contrato esperado da imagem: escutar em `JC_RENDEZVOUS_PORT`, expor WebSocket em `/rendezvous`,
signaling efêmero em `/signaling`, issuer autorizado em `/turn-credentials` e aceitar os secrets
pelos caminhos `JC_TURN_SHARED_SECRET_FILE`, `JC_BRIDGE_PAIRING_ADMIN_KEY_FILE`,
`JC_BRIDGE_SIGNING_KEY_FILE` e `JC_BRIDGE_DESCRIPTOR_FILE`. O app do repo fornece
records assinados, signaling WSS e emissão `turn.issue` limitada a sockets de hosts registrados;
os três paths públicos terminam no mesmo control plane WebSocket. O proxy não falsifica endpoints
nem põe o TURN secret em variável client-facing.

## Operação e diagnóstico

```bash
docker compose ps
docker compose logs --since=15m gateway rendezvous coturn
curl --fail --silent --show-error https://bridge.example.com/healthz
openssl s_client -connect turn.bridge.example.com:443 -servername turn.bridge.example.com </dev/null
```

Os access logs do Nginx ficam desligados para não criar histórico comportamental. Logs de serviço
usam rotação local de `10 MiB x 3`; envie somente métricas/logs operacionais sanitizados para um
coletor, nunca SDP, ICE credentials, pairing token ou shared secret. O healthcheck do rendezvous
abre WebSocket e exige exatamente `{type:"health.ready.result",requestId,ok:true,data:{ready:true,stateLoaded:true}}`
para seu requestId aleatório; qualquer outra mensagem falha. O `/healthz` do gateway é apenas
liveness do edge, enquanto a dependência Compose usa essa readiness do backend. O healthcheck do
coturn cria uma allocation autenticada local com credencial REST temporária. O healthcheck do
gateway agrega sintaxe/listeners e sockets atuais do rendezvous/coturn. Nenhum deles prova DNS,
NAT, firewall ou rota externa.

No bridge, gere um pacote `0600` com credenciais válidas por cinco minutos. O shared secret não sai
do host:

```bash
./scripts/mint-turn-diagnostic-credentials.mjs /caminho-seguro/turn-diagnostic.json
```

Transfira somente esse pacote temporário por canal seguro para a máquina/rede que precisa ser
qualificada e, antes da expiração, rode nela a partir deste checkout:

```bash
./scripts/diagnose-turn-443.sh /caminho-seguro/turn-diagnostic.json
```

O diagnóstico usa o image digest pinado e não imprime credencial nem shared secret. Apague o pacote
após o teste. Uma execução no próprio bridge pode falhar por ausência de hairpin NAT; uma execução
local bem-sucedida também não substitui o aceite WAN na rede-alvo.

O coturn aplica por padrão:

- REST auth (`use-auth-secret`) e realm explícito;
- quatro allocations por username e 100 allocations totais;
- teto de 4 MB/s por sessão e capacidade agregada de 50 MB/s;
- bloqueio de loopback, multicast, faixas privadas, link-local e CGNAT como peers de relay;
- TLS 1.2+; coturn escuta internamente em 5349 e o gateway publica TURN/TLS em 443 por SNI;
- filesystem read-only, sem CLI administrativa e sem software attribute.

O entrypoint do coturn inicia com privilégios mínimos para ler secrets/certificados `0600` e, em
seguida, o próprio coturn troca para `nobody:nogroup`. O bounding set mantém somente leitura DAC,
bind de porta e troca de UID/GID; as demais capabilities ficam removidas.

Esses limites protegem um bridge público de virar proxy para redes privadas. Se o bridge também
precisar atender peers privados por desenho consciente, revise as deny lists e o threat model; não
libere `0.0.0.0/0` por conveniência.

## Renovação TLS

Agende semanalmente (systemd timer ou cron do host), mantendo a execução serializada:

```bash
cd /caminho/para/janjacord/infra/docker && ./scripts/renew-certificate.sh
```

O script roda `certbot renew` e recria Nginx/coturn para carregar o certificado. Conexões WSS e
TURN/TLS ativas podem reconectar durante esse reload; faça-o em janela de menor uso.

## Renovação do descriptor

Antes da expiração anual, renove com a mesma chave de assinatura e redistribua o descriptor:

```bash
./scripts/refresh-descriptor.sh
```

Pairings antigos não são renovados pelo refresh. Eles são one-shot; execute `mint-pairing.sh`
quando precisar autorizar uma nova comunidade. A perda ou troca da signing key muda a identidade
do bridge e exige re-pairing explícito nos clientes.

## Backup e restore

Não há banco de conteúdo, mas os arquivos abaixo são credenciais e estado anti-rollback. O comando
é realmente cifrado para uma chave pública GPG do operador; não chame um `.tar` plaintext de backup
seguro. Confirme o fingerprint completo por um canal independente antes da primeira execução:

```bash
export BACKUP_RECIPIENT_FINGERPRINT='<verified-full-GPG-fingerprint>'
gpg --list-keys "$BACKUP_RECIPIENT_FINGERPRINT"
tar --create --gzip --numeric-owner --file - .env secrets state \
  | gpg --batch --yes --trust-model always --encrypt \
      --recipient "$BACKUP_RECIPIENT_FINGERPRINT" \
      --output "janjabridge-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.gpg"
unset BACKUP_RECIPIENT_FINGERPRINT
```

Teste a descriptografia e o inventário sem extrair antes de depender do arquivo:

```bash
gpg --decrypt janjabridge-YYYYMMDDTHHMMSSZ.tar.gz.gpg | tar --list --gzip >/dev/null
```

Restore deve ocorrer no mesmo path de deployment, com a stack parada. Reaplique explicitamente o
owner registrado por `init.sh`; preservar bytes sem restaurar UID/GID deixa secrets `0600`
ilegíveis para o rendezvous:

```bash
docker compose down
gpg --decrypt /backup/janjabridge-YYYYMMDDTHHMMSSZ.tar.gz.gpg \
  | sudo tar --extract --gzip --numeric-owner --file - -C "$PWD"
restore_uid="$(sudo sed -n 's/^JANJABRIDGE_UID=//p' .env | tail -n 1)"
restore_gid="$(sudo sed -n 's/^JANJABRIDGE_GID=//p' .env | tail -n 1)"
sudo chown "$restore_uid:$restore_gid" .env state
for restored_path in secrets state/rendezvous state/bootstrap-tls state/releases; do
  [ ! -e "$restored_path" ] || sudo chown -R "$restore_uid:$restore_gid" "$restored_path"
done
sudo chown "$restore_uid:$restore_gid" state/bridge-pairing*.json state/bridge-descriptor.json
for restored_dir in secrets state/rendezvous state/bootstrap-tls state/releases; do
  [ ! -d "$restored_dir" ] || sudo chmod 0700 "$restored_dir"
done
sudo find secrets -type f -exec chmod 0600 {} +
sudo chmod 0600 .env state/bridge-pairing*.json
sudo chmod 0644 state/bridge-descriptor.json
docker compose config --quiet
docker compose up -d --no-build --pull never
```

As chaves privadas do Let's Encrypt permanecem com ownership/modes administrados pelo Certbot;
não aplique `chown -R` nelas. Sem `secrets/turn-shared-secret`, credenciais TURN já emitidas deixam
de validar; sem o pairing admin key, novos pairings não podem ser mintados e tokens existentes
não podem ser validados.

O ledger `state/rendezvous/control-state.jsonl` contém revogações assinadas e high-water marks de
epoch/sequence/generation e consumos de pairing one-shot. Cada registro é hash-chained; corrupção ou truncamento não-tail impede
startup, enquanto somente um append final incompleto é removido. Access credentials/proof IDs
expiram, coleções têm cap e o arquivo é compactado por checkpoint atômico/fsync quando cresce.
Perdê-lo reduz a proteção contra rollback; restaure-o junto com os secrets antes de voltar a
publicar o bridge. Um operador com controle total do host ainda pode restaurar ledger+secrets para
um snapshot antigo coerente: esse rollback completo não é detectável pelo próprio bridge. Clientes
devem conservar high-water e revogações assinadas pela authority e falhar fechados se esse estado
local estabelecido faltar ou estiver corrompido.

## Update, rollback e uninstall

As imagens de base e serviços externos geradas por `init.sh` estão pinadas por tag legível **e**
digest. Não troque esses valores por tags flutuantes. `JANJABRIDGE_IMAGE=...:local` é somente a
primeira build a partir do checkout; antes de promoção, fixe o container que está rodando com:

```bash
./scripts/snapshot-release.sh pre-update
```

O snapshot grava os IDs imutáveis `sha256:` dos três containers runtime em
`state/releases/pre-update.env` e um checksum. Faça também o backup cifrado acima. Para rollout de
uma imagem publicada, altere `JANJABRIDGE_IMAGE` para `registry/...@sha256:<digest>` e mantenha
Nginx/coturn/certbot por digest. Então:

```bash
docker compose pull rendezvous gateway coturn certbot
docker compose config --quiet
docker compose up -d --no-build
docker compose ps
# Gere o pacote temporário e execute diagnose-turn-443.sh na rede externa, como acima.
```

Se readiness ou smoke falhar, rollback real usa o snapshot de IDs locais, sem rebuild e sem pull:

```bash
cp .env ".env.failed-$(date -u +%Y%m%dT%H%M%SZ)"
cp state/releases/pre-update.env .env
sha256sum --check state/releases/pre-update.env.sha256
docker compose config --quiet
docker compose up -d --no-build --pull never --force-recreate
docker compose ps
```

Restaure o backup cifrado somente se o rollout também migrou/rotacionou secret, certificado ou
ledger; um rollback de imagem normal deve preservar o state atual. Guarde snapshots enquanto a
imagem referenciada existir no host; `docker image prune` pode remover a única cópia de um ID local.

Uninstall não apaga secrets automaticamente:

```bash
docker compose down --remove-orphans
```

Depois de confirmar o backup e que nenhum cliente usa o bridge, remova manualmente `.env`,
`secrets/` e `state/`. Revogue o certificado ACME quando a chave/domínio não será reutilizada e
feche as portas do firewall. `docker compose down -v` não é necessário porque a stack usa bind
mounts explícitos.

## Limites de aceite

`docker compose config` valida estrutura e interpolação, não prova alocação TURN através de NAT.
O gate de produção continua exigindo: certificado público válido, credenciais REST temporárias
emitidas pelo app, `diagnose-turn-443.sh` executado na rede restritiva, allocation TURN real pelo
cliente JanjaCord em outra rede, teste relay-only sem candidate direto e
failover com dois JanjaBridges independentes.
