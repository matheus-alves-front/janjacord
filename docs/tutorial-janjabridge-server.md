# Tutorial: colocar um servidor JanjaBridge no ar

Este guia coloca um JanjaBridge comunitário em um host Linux público usando o bundle Docker do
repositório. No final, você terá uma rota WSS/TURN que pode ser adicionada a uma comunidade no
desktop JanjaCord por um pairing temporário.

O JanjaBridge é infraestrutura auxiliar. Ele não hospeda a comunidade, não recebe mensagens,
anexos, voz, vídeo ou identidade local. Ele pode observar metadados de transporte necessários
para operar a rede; o conteúdo da comunidade continua E2EE.

## 1. O que você precisa

- host Linux público com Docker Engine e Docker Compose v2;
- Node.js 22+ e OpenSSL no host;
- executar `init.sh` e Docker com o mesmo usuário não-root;
- relógio sincronizado por NTP;
- dois registros DNS A apontando para o mesmo IPv4 público:
  - `bridge.example.com` para HTTPS/WSS;
  - `turn.bridge.example.com` exclusivo para TURN, sem proxy/CDN;
- firewall/NAT encaminhando:
  - `80/tcp` e `443/tcp`;
  - `3478/tcp` e `3478/udp`;
  - `49160-49259/udp` para as allocations TURN.

Não publique portas administrativas do Docker ou do coturn.

## 2. Inicialize uma instalação nova

Use um checkout do JanjaCord no host e entre no bundle:

```bash
cd /caminho/para/janjacord/infra/docker
```

O script abaixo cria o `.env`, secrets, descriptor assinado, pairing inicial e certificado
bootstrap. Troque os quatro valores pelos seus dados reais:

```bash
./scripts/init.sh bridge.example.com ops@example.com 203.0.113.10 turn.bridge.example.com
```

Os argumentos são, nesta ordem: domínio WSS, email ACME, IPv4 público e domínio TURN. O script
recusa rodar como root e recusa sobrescrever uma instalação já inicializada.

## 3. Suba a stack e emita o certificado público

```bash
docker compose config --quiet
docker compose up -d --build
./scripts/issue-certificate.sh
docker compose ps
```

O primeiro `up` usa um certificado bootstrap autoassinado apenas para o desafio ACME. Não
compartilhe pairing antes de `issue-certificate.sh` concluir. O script deve terminar informando
que o certificado foi instalado e os serviços devem aparecer no `docker compose ps`.

Para diagnosticar uma falha de subida ou validação:

```bash
docker compose logs --since=15m gateway rendezvous coturn
```

Confira primeiro DNS, portas 80/443, o certificado dos dois hostnames e o relógio do host.

## 4. Gere um pairing para uma comunidade

O pairing inicial é one-shot e dura 24 horas. Para gerar outro quando necessário:

```bash
./scripts/mint-pairing.sh 24
```

O comando informa o arquivo `state/bridge-pairing-<timestamp>.json`. Compartilhe o conteúdo
desse arquivo uma única vez, por um canal confiável. Nunca compartilhe:

- `.env`;
- `secrets/bridge-pairing-admin-key`;
- `secrets/turn-shared-secret`;
- `secrets/bridge-signing-key.pem`;
- qualquer chave privada de TLS.

Se o pairing expirar ou já tiver sido usado, gere um novo. O descriptor público pode ser
distribuído, mas o pairing continua sendo uma credencial de autorização.

## 5. Conecte ao desktop JanjaCord

No dispositivo que hospeda a comunidade:

1. Abra `Configurações` → `Conectividade`.
2. Em `JanjaBridges`, escolha `Já tenho pairing` — ou abra `Tutorial servidor JanjaBridge` para
   retornar a este fluxo.
3. Cole o JSON inteiro de `state/bridge-pairing-*.json`.
4. Escolha `Adicionar`.
5. Confirme `JanjaBridge adicionado` e a rota validada.

O app verifica assinatura, validade e endpoint antes de salvar. O pairing não entra no convite,
nos logs ou no descriptor público.

## 6. Operação contínua

Renove o certificado antes da expiração:

```bash
cd /caminho/para/janjacord/infra/docker
./scripts/renew-certificate.sh
```

Antes da expiração anual do descriptor, mantenha a mesma chave e execute:

```bash
./scripts/refresh-descriptor.sh
```

O refresh do descriptor não renova pairings. Gere novos pairings com `mint-pairing.sh` quando
precisar autorizar uma comunidade adicional.

O bundle detalhado, incluindo backup, restore, update, rollback e diagnóstico TURN, está em
[`infra/docker/README.md`](../infra/docker/README.md).
