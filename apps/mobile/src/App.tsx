/**
 * JanjaCord Mobile — React Native/Expo (ADR-009). FLUXO REAL:
 * identidade (SecureStore + Argon2), conexão ao host (WebSocket nativo),
 * mensagens E2EE via módulo nativo MLS (UniFFI).
 *
 * BUILD: dev build obrigatório (expo run:android / eas build) — Expo Go não tem
 * o módulo nativo JanjacordCrypto nem WebRTC.
 */
import React, { useEffect, useState } from "react";
import {
  SafeAreaView,
  Text,
  TextInput,
  TouchableOpacity,
  View,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
} from "react-native";
import { hasIdentity, createIdentityMobile, unlockIdentityMobile, type MobileIdentity } from "./identity";
import { HostClientRN } from "./networking";
import { endpointFromInvite } from "./invite";
import { mls, assertNativeCrypto } from "./crypto";

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#0b0d10", padding: 24 },
  title: { color: "#fff", fontSize: 24, fontWeight: "600", marginBottom: 8 },
  sub: { color: "#8b919a", fontSize: 13, marginBottom: 20, lineHeight: 18 },
  input: { backgroundColor: "#090b0e", borderColor: "#2a2f38", borderWidth: 1, borderRadius: 8, color: "#e6e8eb", padding: 12, marginBottom: 12 },
  button: { backgroundColor: "#4f46e5", borderRadius: 8, padding: 14, alignItems: "center", marginBottom: 8 },
  buttonText: { color: "#fff", fontWeight: "500" },
  secondary: { backgroundColor: "#1a1e26", borderRadius: 8, padding: 14, alignItems: "center", marginBottom: 8 },
  secondaryText: { color: "#c8ccd2" },
  channel: { backgroundColor: "#14181f", borderRadius: 8, padding: 12, marginBottom: 8, flexDirection: "row", alignItems: "center" },
  channelText: { color: "#e6e8eb", fontSize: 14 },
  message: { marginBottom: 12 },
  messageAuthor: { color: "#9aa1ab", fontSize: 11, marginBottom: 2 },
  messageText: { color: "#e6e8eb", fontSize: 14 },
  composer: { backgroundColor: "#090b0e", borderColor: "#2a2f38", borderWidth: 1, borderRadius: 8, color: "#e6e8eb", padding: 12, marginTop: 8 },
  error: { color: "#f87171", fontSize: 12, marginBottom: 8 },
});

interface Msg { author: string; text: string; self?: boolean }

const gidHex = (channelId: string) => Buffer.from(channelId.replace(/-/g, ""), "hex").toString("hex");

export default function App() {
  const [phase, setPhase] = useState<"loading" | "onboarding" | "unlock" | "home" | "chat">("loading");
  const [identity, setIdentity] = useState<MobileIdentity | null>(null);
  const [nickname, setNickname] = useState("");
  const [password, setPassword] = useState("");
  const [inviteKey, setInviteKey] = useState("");
  const [messages, setMessages] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const hostRef = React.useRef<HostClientRN | null>(null);
  const groupRef = React.useRef<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        await assertNativeCrypto();
        setPhase((await hasIdentity()) ? "unlock" : "onboarding");
      } catch (e) {
        setError((e as Error).message);
        setPhase("onboarding");
      }
    })();
  }, []);

  const joinServer = async () => {
    setBusy(true);
    setError(null);
    try {
      const id = identity!;
      const endpoint = endpointFromInvite(inviteKey.trim());
      if (!endpoint) {
        throw new Error(
          "Este convite não carrega o endereço do server (JC1). Peça um convite novo do host — o convite atual (JC2) já vem com tudo embutido."
        );
      }
      const client = new HostClientRN();
      const hello = await client.connect(endpoint, id.identityId);
      if (!(hello as { ok?: boolean })?.ok) throw new Error("host não respondeu o hello");
      const join = await client.request({ type: "server.join", inviteKey: inviteKey.trim() });
      if (!(join as { ok?: boolean })?.ok) throw new Error((join as { error?: { message?: string } }).error?.message ?? "join falhou");
      const state = (join as { data: any }).data;
      const general = state.channels.find((c: any) => c.type === "text");
      hostRef.current = client;
      groupRef.current = gidHex(general.id);

      // publica key package e entra no grupo MLS (welcome pendente)
      const kp = await mls.generateKeyPackage(id.seedHex, id.identityId);
      await client.request({ type: "keypackage.upload", keyPackageB64: kp });
      const welcome = await client.request({ type: "welcome.pending" });
      const w = welcome as { ok?: boolean; data?: { welcomeB64?: string } };
      if (w.ok && w.data?.welcomeB64) {
        const joined = JSON.parse(await mls.joinGroup(id.seedHex, id.identityId, w.data.welcomeB64));
        console.log("grupo MLS:", joined.epoch);
      }

      // recebe mensagens e decifra
      client.onEvent(async (evt: any) => {
        if (evt?.type === "envelope.deliver") {
          const dec = JSON.parse(await mls.decrypt(id.seedHex, id.identityId, groupRef.current!, evt.envelope.ciphertext));
          const text = Buffer.from(dec.plaintextB64, "base64").toString("utf8");
          setMessages((prev) => [...prev, { author: evt.envelope.sender.slice(0, 8), text }]);
          await client.request({ type: "message.ackConsumed", messageId: evt.envelope.messageId });
        } else if (evt?.type === "welcome.deliver") {
          await mls.joinGroup(id.seedHex, id.identityId, evt.welcomeB64);
          console.log("welcome aplicado (epoch avançou)");
        }
      });

      setPhase("chat");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const sendMessage = async () => {
    if (!draft.trim() || !identity || !hostRef.current || !groupRef.current) return;
    const text = draft.trim();
    setDraft("");
    try {
      const enc = JSON.parse(await mls.encrypt(identity.seedHex, identity.identityId, groupRef.current, Buffer.from(text).toString("base64")));
      const state = (await hostRef.current.request({ type: "server.state" })) as { ok?: boolean; data?: any };
      const data = state.data;
      const channel = data?.channels?.find((c: any) => c.type === "text");
      const env = {
        protocolVersion: 1,
        messageId: (await import("expo-crypto")).randomUUID(),
        serverId: data?.serverId,
        channelId: channel?.id,
        sender: identity.identityId,
        cryptoEpoch: enc.epoch,
        audience: { algo: "sha256", commitment: "", members: data?.members?.map((m: any) => m.identityId) ?? [] },
        ciphertext: enc.ciphertextB64,
        attachments: [],
        ordering: { seq: 1 },
        createdAt: Date.now(),
      };
      await hostRef.current.send("envelope.send", env);
      setMessages((prev) => [...prev, { author: "você", text, self: true }]);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <SafeAreaView style={styles.root}>
      {phase === "loading" && <ActivityIndicator color="#fff" />}
      {error && <Text style={styles.error}>{error}</Text>}

      {phase === "onboarding" && (
        <ScrollView>
          <Text style={styles.title}>JanjaCord</Text>
          <Text style={styles.sub}>Comunicador privado de comunidades. Sem email, sem telefone. Mensagens efêmeras E2EE.</Text>
          <TextInput style={styles.input} placeholder="Nickname" placeholderTextColor="#5b616b" value={nickname} onChangeText={setNickname} autoCapitalize="none" />
          <TextInput style={styles.input} placeholder="Senha (mín. 8)" placeholderTextColor="#5b616b" secureTextEntry value={password} onChangeText={setPassword} />
          <TouchableOpacity
            style={styles.button}
            disabled={busy}
            onPress={async () => {
              setBusy(true);
              try {
                setIdentity(await createIdentityMobile(nickname, password));
                setPhase("home");
              } catch (e) { setError((e as Error).message); }
              setBusy(false);
            }}
          >
            <Text style={styles.buttonText}>Criar identidade</Text>
          </TouchableOpacity>
        </ScrollView>
      )}

      {phase === "unlock" && (
        <View>
          <Text style={styles.title}>Desbloquear</Text>
          <TextInput style={styles.input} placeholder="Senha" placeholderTextColor="#5b616b" secureTextEntry value={password} onChangeText={setPassword} />
          <TouchableOpacity
            style={styles.button}
            onPress={async () => {
              setBusy(true);
              try { setIdentity(await unlockIdentityMobile(password)); setPhase("home"); }
              catch (e) { setError((e as Error).message); }
              setBusy(false);
            }}
          >
            <Text style={styles.buttonText}>Desbloquear</Text>
          </TouchableOpacity>
        </View>
      )}

      {phase === "home" && (
        <ScrollView>
          <Text style={styles.title}>Servers</Text>
          <Text style={styles.sub}>Entre com um convite do seu desktop (host self-hosted). O convite já carrega o endereço — é só colar.</Text>
          <TextInput style={styles.input} placeholder="Convite (JC2-…)" placeholderTextColor="#5b616b" value={inviteKey} onChangeText={setInviteKey} autoCapitalize="none" />
          <TouchableOpacity style={styles.button} disabled={busy} onPress={joinServer}>
            <Text style={styles.buttonText}>{busy ? "Entrando…" : "Entrar com convite"}</Text>
          </TouchableOpacity>
        </ScrollView>
      )}

      {phase === "chat" && (
        <View style={{ flex: 1 }}>
          <View style={{ flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <TouchableOpacity onPress={() => setPhase("home")}><Text style={styles.secondaryText}>← Servers</Text></TouchableOpacity>
            <Text style={styles.title}># general</Text>
            <View />
          </View>
          <ScrollView style={{ flex: 1 }}>
            {messages.map((m, i) => (
              <View key={i} style={styles.message}>
                <Text style={styles.messageAuthor}>{m.author}</Text>
                <Text style={styles.messageText}>{m.text}</Text>
              </View>
            ))}
          </ScrollView>
          <View style={{ flexDirection: "row", gap: 8 }}>
            <TextInput style={[styles.composer, { flex: 1, marginTop: 0 }]} placeholder="Mensagem efêmera…" placeholderTextColor="#5b616b" value={draft} onChangeText={setDraft} onSubmitEditing={sendMessage} />
            <TouchableOpacity style={styles.button} onPress={sendMessage}><Text style={styles.buttonText}>Enviar</Text></TouchableOpacity>
          </View>
        </View>
      )}
    </SafeAreaView>
  );
}
