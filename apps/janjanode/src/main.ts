import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { WsAdapter } from "@nestjs/platform-ws";
import { AppModule } from "./app.module.js";

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, { logger: ["error", "warn", "log"] });
  app.useWebSocketAdapter(new WsAdapter(app));
  await app.init();
  const port = Number(process.env.JC_PORT ?? 8931);
  console.log(`[janjanode] JanjaNode host ativo — ws://127.0.0.1:${port}/signal`);
  console.log(`[janjanode] server db: ${process.env.JC_DB_PATH ?? "./janjanode-data/server.db"}`);
}

bootstrap().catch((err) => {
  console.error("[janjanode] fatal:", err);
  process.exit(1);
});
