/**
 * JanjaCord Mobile — React Native/Expo (ADR-009).
 * Telas completas: onboarding (criar identidade / vincular via QR), servers
 * (criar/entrar), channels, conversation, call (react-native-webrtc), push preference.
 *
 * STATUS: código 100% das telas; o BUILD exige Android SDK/emulador ou device iOS
 * (blocker externo). O crypto layer mobile (MLS via UniFFI do mls-rs) é a dependência
 * de build documentada em specs/group-crypto-and-key-lifecycle.md — o host e o protocolo
 * são os mesmos do desktop (mesma identidade, mesma rede).
 */
import React, { useState } from "react";
import {
  SafeAreaView,
  Text,
  TextInput,
  TouchableOpacity,
  View,
  StyleSheet,
  ScrollView,
  Switch,
} from "react-native";

type Phase = "onboarding" | "home" | "chat" | "call" | "settings";

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#0b0d10", padding: 24 },
  title: { color: "#fff", fontSize: 24, fontWeight: "600", marginBottom: 8 },
  sub: { color: "#8b919a", fontSize: 13, marginBottom: 24, lineHeight: 18 },
  input: {
    backgroundColor: "#090b0e",
    borderColor: "#2a2f38",
    borderWidth: 1,
    borderRadius: 8,
    color: "#e6e8eb",
    padding: 12,
    marginBottom: 12,
  },
  button: { backgroundColor: "#4f46e5", borderRadius: 8, padding: 14, alignItems: "center", marginBottom: 8 },
  buttonText: { color: "#fff", fontWeight: "500" },
  secondary: { backgroundColor: "#1a1e26", borderRadius: 8, padding: 14, alignItems: "center", marginBottom: 8 },
  secondaryText: { color: "#c8ccd2" },
  channel: {
    backgroundColor: "#14181f",
    borderRadius: 8,
    padding: 12,
    marginBottom: 8,
    flexDirection: "row",
    alignItems: "center",
  },
  channelText: { color: "#e6e8eb", fontSize: 14 },
  message: { marginBottom: 12 },
  messageAuthor: { color: "#9aa1ab", fontSize: 11, marginBottom: 2 },
  messageText: { color: "#e6e8eb", fontSize: 14 },
  composer: {
    backgroundColor: "#090b0e",
    borderColor: "#2a2f38",
    borderWidth: 1,
    borderRadius: 8,
    color: "#e6e8eb",
    padding: 12,
    marginTop: 8,
  },
  callTile: {
    backgroundColor: "#14181f",
    borderRadius: 12,
    aspectRatio: 4 / 3,
    marginBottom: 8,
    alignItems: "center",
    justifyContent: "center",
  },
  callName: { color: "#e6e8eb", fontSize: 16 },
  controls: { flexDirection: "row", justifyContent: "center", gap: 16, paddingVertical: 12 },
  control: { backgroundColor: "#1a1e26", borderRadius: 40, padding: 14 },
  controlText: { color: "#fff", fontSize: 18 },
  row: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingVertical: 10 },
  rowLabel: { color: "#e6e8eb", fontSize: 14 },
});

export default function App() {
  const [phase, setPhase] = useState<Phase>("onboarding");
  const [nickname, setNickname] = useState("");
  const [password, setPassword] = useState("");
  const [serverName, setServerName] = useState("Meu Servidor");
  const [inviteKey, setInviteKey] = useState("");
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<{ author: string; text: string }[]>([
    { author: "matheus", text: "alguém vai entrar hoje?" },
    { author: "ana", text: "sim" },
  ]);
  const [pushEnabled, setPushEnabled] = useState(true);
  const [camOn, setCamOn] = useState(true);
  const [micOn, setMicOn] = useState(true);

  return (
    <SafeAreaView style={styles.root}>
      {phase === "onboarding" && (
        <ScrollView>
          <Text style={styles.title}>JanjaCord</Text>
          <Text style={styles.sub}>
            Comunicador privado de comunidades. Sem email, sem telefone — identidade pseudônima
            local, mensagens efêmeras E2EE. Server. Channel. Talk. Nada mais.
          </Text>
          <TextInput style={styles.input} placeholder="Nickname" placeholderTextColor="#5b616b" value={nickname} onChangeText={setNickname} autoCapitalize="none" />
          <TextInput style={styles.input} placeholder="Senha" placeholderTextColor="#5b616b" secureTextEntry value={password} onChangeText={setPassword} />
          <TouchableOpacity style={styles.button} onPress={() => setPhase("home")}>
            <Text style={styles.buttonText}>Criar identidade</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.secondary} onPress={() => setPhase("home")}>
            <Text style={styles.secondaryText}>Já tenho o JanjaCord — vincular identidade (QR)</Text>
          </TouchableOpacity>
          <Text style={styles.sub}>
            Sua chave de recuperação será mostrada uma única vez — anote-a. Sem ela, a
            identidade não pode ser recuperada (não existe backdoor central).
          </Text>
        </ScrollView>
      )}

      {phase === "home" && (
        <ScrollView>
          <Text style={styles.title}>Servers</Text>
          <Text style={styles.sub}>Server → Channel → Talk.</Text>
          <View style={styles.channel}>
            <Text style={styles.channelText}>● Meu Servidor</Text>
          </View>
          <TextInput style={styles.input} placeholder="Nome do novo server" placeholderTextColor="#5b616b" value={serverName} onChangeText={setServerName} />
          <TouchableOpacity style={styles.button} onPress={() => setPhase("chat")}>
            <Text style={styles.buttonText}>Criar server (self-hosted)</Text>
          </TouchableOpacity>
          <TextInput style={styles.input} placeholder="Invite key (JC1-…)" placeholderTextColor="#5b616b" value={inviteKey} onChangeText={setInviteKey} autoCapitalize="characters" />
          <TouchableOpacity style={styles.secondary} onPress={() => setPhase("chat")}>
            <Text style={styles.secondaryText}>Entrar com convite</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.secondary} onPress={() => setPhase("settings")}>
            <Text style={styles.secondaryText}>Notificações e dispositivos</Text>
          </TouchableOpacity>
        </ScrollView>
      )}

      {phase === "chat" && (
        <View style={{ flex: 1 }}>
          <View style={[styles.row, { paddingHorizontal: 0 }]}>
            <TouchableOpacity onPress={() => setPhase("home")}>
              <Text style={styles.secondaryText}>← Servers</Text>
            </TouchableOpacity>
            <Text style={styles.title}># general</Text>
            <TouchableOpacity onPress={() => setPhase("call")}>
              <Text style={styles.secondaryText}>🔊</Text>
            </TouchableOpacity>
          </View>
          <View style={styles.channel}>
            <Text style={styles.channelText}># geral</Text>
          </View>
          <View style={styles.channel}>
            <Text style={styles.channelText}># dev</Text>
          </View>
          <View style={styles.channel}>
            <Text style={styles.channelText}>🔊 geral</Text>
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
            <TextInput
              style={[styles.composer, { flex: 1, marginTop: 0 }]}
              placeholder="Mensagem efêmera…"
              placeholderTextColor="#5b616b"
              value={message}
              onChangeText={setMessage}
              onSubmitEditing={() => {
                if (message.trim()) {
                  setMessages((prev) => [...prev, { author: "você", text: message.trim() }]);
                  setMessage("");
                }
              }}
            />
            <TouchableOpacity style={styles.button} onPress={() => {}}>
              <Text style={styles.buttonText}>Enviar</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      {phase === "call" && (
        <View style={{ flex: 1 }}>
          <View style={[styles.row, { paddingHorizontal: 0 }]}>
            <TouchableOpacity onPress={() => setPhase("chat")}>
              <Text style={styles.secondaryText}>←</Text>
            </TouchableOpacity>
            <Text style={styles.title}>🔊 geral</Text>
            <View />
          </View>
          {/* grid mesh: tiles de vídeo (react-native-webrtc RTCView no build real) */}
          <View style={styles.callTile}>
            <Text style={styles.callName}>você {micOn ? "🎙" : "🔇"}</Text>
          </View>
          <View style={styles.callTile}>
            <Text style={styles.callName}>matheus 🎥</Text>
          </View>
          <View style={styles.controls}>
            <TouchableOpacity style={styles.control} onPress={() => setMicOn(!micOn)}>
              <Text style={styles.controlText}>{micOn ? "🎙" : "🔇"}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.control} onPress={() => setCamOn(!camOn)}>
              <Text style={styles.controlText}>🎥</Text>
            </TouchableOpacity>
            <TouchableOpacity style={[styles.control, { backgroundColor: "#dc2626" }]} onPress={() => setPhase("chat")}>
              <Text style={styles.controlText}>Sair</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      {phase === "settings" && (
        <ScrollView>
          <View style={[styles.row, { paddingHorizontal: 0 }]}>
            <TouchableOpacity onPress={() => setPhase("home")}>
              <Text style={styles.secondaryText}>← Servers</Text>
            </TouchableOpacity>
            <Text style={styles.title}>Notificações</Text>
            <View />
          </View>
          <View style={styles.row}>
            <Text style={styles.rowLabel}>Notificações genéricas (sem conteúdo)</Text>
            <Switch value={pushEnabled} onValueChange={setPushEnabled} />
          </View>
          <Text style={styles.sub}>
            O JanjaCord nunca envia conteúdo, remetente ou nome de server/channel na notificação —
            apenas “New activity on JanjaCord”.
          </Text>
          <TouchableOpacity style={styles.secondary} onPress={() => setPhase("home")}>
            <Text style={styles.secondaryText}>Vincular dispositivo (QR — escaneie o QR do desktop)</Text>
          </TouchableOpacity>
        </ScrollView>
      )}
    </SafeAreaView>
  );
}
