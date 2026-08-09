/**
 * Configuração do JanjaNode (host do server).
 * O host recebe a dbKey do dono (vault local) — nunca plaintext adicional (ADR-002/016).
 */
export interface JanjaNodeConfig {
  /** Porta do signaling WebSocket. */
  port: number;
  /** Caminho do banco SQLCipher do server. */
  dbPath: string;
  /** Raw key 32B do SQLCipher (dbKey do vault do dono). */
  dbKey: Buffer;
  /** Identidade do Owner/Primary Host (autoridade inicial). */
  ownerIdentity: string;
  /** Nickname do owner no server. */
  ownerNickname: string;
  /** Nome do server (criado no primeiro boot). */
  serverName: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): JanjaNodeConfig {
  const dbKeyHex = env.JC_DB_KEY ?? "";
  const dbKey = Buffer.from(dbKeyHex, "hex");
  if (dbKey.length !== 32) throw new Error("JC_DB_KEY must be 32 bytes hex");
  return {
    port: Number(env.JC_PORT ?? 8931),
    dbPath: env.JC_DB_PATH ?? "./janjanode-data/server.db",
    dbKey,
    ownerIdentity: env.JC_OWNER_IDENTITY ?? "",
    ownerNickname: env.JC_OWNER_NICKNAME ?? "owner",
    serverName: env.JC_SERVER_NAME ?? "Meu Servidor",
  };
}
