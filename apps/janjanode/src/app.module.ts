import { randomUUID } from "node:crypto";
import { Module } from "@nestjs/common";
import { Store } from "./store.js";
import { ServerService } from "./server.service.js";
import { SignalingGateway } from "./gateway.js";
import { loadConfig, type JanjaNodeConfig } from "./config.js";

export const CONFIG = Symbol("JANJANODE_CONFIG");

/** serverId persistido no banco cifrado (único por host). */
function ensureServerId(store: Store): string {
  const row = store.raw.prepare("SELECT value FROM server_meta WHERE key = 'server_id'").get() as
    | { value: string }
    | undefined;
  if (row) return row.value;
  const id = randomUUID();
  store.raw.prepare("INSERT INTO server_meta (key, value) VALUES ('server_id', ?)").run(id);
  return id;
}

@Module({
  providers: [
    { provide: CONFIG, useFactory: () => loadConfig() },
    { provide: Store, useFactory: (cfg: JanjaNodeConfig) => new Store(cfg.dbPath, cfg.dbKey), inject: [CONFIG] },
    {
      provide: ServerService,
      useFactory: (store: Store, cfg: JanjaNodeConfig) => {
        const svc = new ServerService(
          store,
          ensureServerId(store),
          cfg.dbPath,
          cfg.ownerIdentity,
          cfg.ownerNickname,
          cfg.serverName,
        );
        svc.bootstrap();
        svc.startRetentionLoop();
        svc.startAttachmentCleanup();
        return svc;
      },
      inject: [Store, CONFIG],
    },
    SignalingGateway,
  ],
})
export class AppModule {}
