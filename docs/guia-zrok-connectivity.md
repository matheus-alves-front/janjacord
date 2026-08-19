# Guia: publicar sua comunidade com Zrok (sem abrir portas)

Este guia explica como publicar o JanjaNode local por um túnel Zrok — uma das opções de
"Sem abrir portas" do Conectividade no desktop JanjaCord. No final, membros sem Zrok instalado
conseguem entrar usando somente o convite da comunidade.

O Zrok é um túnel de rota direta do host. Ele **não** é JanjaBridge: não participa do pareamento,
do rendezvous, da assinatura do host nem do TURN. O conteúdo da comunidade continua criptografado
de ponta a ponta; o serviço Zrok pode observar apenas metadados de transporte e disponibilidade.

## 1. O que você precisa

- Desktop JanjaCord (Windows, Linux ou macOS);
- o comando `zrok2` instalado (veja abaixo);
- uma conta Zrok **hosted** (https://zrok.io ou o console da NetFoundry) ou uma instância
  **self-hosted** (avançado, seção 5);
- o ambiente Zrok habilitado uma única vez no seu terminal.

### Instalar o `zrok2` (versão 2)

No Linux (RPM/DEB), o comando oficial:

```bash
curl -sSf https://get.openziti.io/install.bash | sudo bash -s zrok2
```

Sem sudo, baixe o binário do [GitHub releases](https://github.com/openziti/zrok/releases) e
coloque em uma pasta do seu PATH:

```bash
mkdir -p ~/bin && install zrok2 ~/bin/ && export PATH="$HOME/bin:$PATH"
```

Confira com `zrok2 version`. O comando legado `zrok` (v1) **não** é usado por este guia.

## 2. Criar a conta e habilitar o ambiente

1. Crie sua conta em https://zrok.io (o token de conta fica no painel).
2. No terminal, habilite o ambiente uma única vez:

```bash
zrok2 enable <seu_token_de_conta> --headless
```

3. Confira: `zrok2 status` deve mostrar `Account Token <<SET>>` na seção Environment.

O token de conta é segredo do ambiente Zrok. O JanjaCord **nunca** pede nem armazena esse token:
ele reutiliza o ambiente `~/.zrok2` que você habilitou. Se o app detectar que o ambiente ainda
não foi habilitado, ele mostra este comando para você rodar no terminal.

## 3. Publicar a comunidade pelo app

1. Abra o JanjaCord e crie ou entre na comunidade (Primary Host).
2. Vá em **Configurações → Conectividade** e escolha **Zrok — Sem abrir portas**.
3. Dê um nome para a rota (ex.: `minha-comunidade`). Esse nome vira o endereço público e é
   **estável entre sessões**.
4. Ative a rota. O app reserva o nome, sobe o túnel e valida o endereço `wss://…/signal` antes
   de incluí-lo em novos convites.

Membros conectam pelo convite normalmente — sem instalar Zrok.

## 4. O que significa "rota persistente"

Com o Zrok, o endereço público não muda entre reinícios do app: o nome reservado permanece na sua
conta. Quando o app reinicia, a rota volta para o mesmo endereço. Convites antigos continuam
válidos enquanto a rota estiver ativa.

Ao encerrar a rota (ou fechar o app), o endereço deixa de responder; ele volta quando você ativar
a rota de novo.

## 5. Opção avançada: instância self-hosted

Se a comunidade prefere não depender do serviço hosted, um operador pode subir a própria instância
Zrok (controller via `zrok2 controller` ou o [Helm chart oficial](https://github.com/openziti/zrok)).
Nesse caso:

1. Aponte o cliente para a instância **antes** de habilitar:

```bash
zrok2 config set apiEndpoint https://sua-instancia.example.com
zrok2 enable <token_da_instancia> --headless
```

2. Use o app normalmente — o fluxo é o mesmo.

O JanjaCord não provisiona a instância: subir, manter e garantir disponibilidade do servidor é
responsabilidade do operador.

## 6. Limites e privacidade

- O Zrok é um **terceiro no caminho de transporte**: vê tráfego e disponibilidade, mas não o
  conteúdo (E2EE).
- A rota pública é aberta: qualquer pessoa com o endereço alcança a camada pública do túnel. A
  autorização real de entrada na comunidade continua sendo feita pelo protocolo JanjaCord
  (convite assinado).
- Zrok **não fornece TURN**. Voz e vídeo continuam em conexão direta (WebRTC) e podem falhar em
  NAT restritivo; use JanjaBridge/TURN para mídia confiável.
- Não há SLA de disponibilidade; trate o túnel como ferramenta operacional, não como serviço
  gerenciado.

## Referência

- Docs oficiais Zrok: https://netfoundry.io/docs/zrok/
- Instalação: https://netfoundry.io/docs/zrok/how-tos/install/linux
- Habilitação: https://netfoundry.io/docs/zrok/get-started/enable-env/
- Nomes persistentes: https://netfoundry.io/docs/zrok/how-tos/shares/manage-reserved-names/
- Tutorial de servidor JanjaBridge (infraestrutura comunitária): [tutorial-janjabridge-server.md](tutorial-janjabridge-server.md)
