/**
 * JanjaCord Mobile — React Native/Expo (ADR-009).
 * STATUS: scaffold estrutural; BUILD exige Android SDK/emulador ou device iOS
 * (blocker externo nesta estação — ver master-plan). WebRTC/crypto exigem dev build
 * (expo-dev-client), nunca Expo Go.
 *
 * Telas: Onboarding (criar identidade / vincular existente via QR), Servers, Channels,
 * Conversation, Call. Visual ≈ desktop via design-tokens (não reutiliza componentes DOM).
 */
import React, { useState } from "react";
import { SafeAreaView, Text, TextInput, TouchableOpacity, View, StyleSheet } from "react-native";

type Phase = "onboarding" | "home" | "chat";

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: "#0b0d10", padding: 24, justifyContent: "center" },
  title: { color: "#fff", fontSize: 24, fontWeight: "600", marginBottom: 8 },
  sub: { color: "#8b919a", fontSize: 13, marginBottom: 24 },
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
  secondary: { backgroundColor: "#1a1e26", borderRadius: 8, padding: 14, alignItems: "center" },
  secondaryText: { color: "#c8ccd2" },
});

export default function App() {
  const [phase, setPhase] = useState<Phase>("onboarding");
  const [nickname, setNickname] = useState("");
  const [password, setPassword] = useState("");

  return (
    <SafeAreaView style={styles.root}>
      {phase === "onboarding" && (
        <>
          <Text style={styles.title}>JanjaCord</Text>
          <Text style={styles.sub}>
            Comunicador privado de comunidades. Sem email, sem telefone — identidade pseudônima
            local, mensagens efêmeras E2EE.
          </Text>
          <TextInput style={styles.input} placeholder="Nickname" placeholderTextColor="#5b616b" value={nickname} onChangeText={setNickname} autoCapitalize="none" />
          <TextInput style={styles.input} placeholder="Senha" placeholderTextColor="#5b616b" secureTextEntry value={password} onChangeText={setPassword} />
          <TouchableOpacity style={styles.button} onPress={() => setPhase("home")}>
            <Text style={styles.buttonText}>Criar identidade</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.secondary} onPress={() => setPhase("home")}>
            <Text style={styles.secondaryText}>Já tenho o JanjaCord — vincular identidade (QR)</Text>
          </TouchableOpacity>
        </>
      )}
      {phase === "home" && (
        <>
          <Text style={styles.title}>Servers</Text>
          <Text style={styles.sub}>Server → Channel → Talk. Nada mais.</Text>
          <TouchableOpacity style={styles.button} onPress={() => setPhase("chat")}>
            <Text style={styles.buttonText}>Criar server</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.secondary} onPress={() => setPhase("chat")}>
            <Text style={styles.secondaryText}>Entrar com invite key</Text>
          </TouchableOpacity>
        </>
      )}
      {phase === "chat" && (
        <>
          <Text style={styles.title}># general</Text>
          <View style={{ flex: 1 }} />
          <TextInput style={[styles.input, { marginBottom: 0 }]} placeholder="Mensagem efêmera…" placeholderTextColor="#5b616b" />
        </>
      )}
    </SafeAreaView>
  );
}
