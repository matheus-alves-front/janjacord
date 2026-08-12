export * from "./envelope.js";
export * from "./domain.js";
export * from "./commands.js";
export * from "./connectivity.js";

import { z } from "zod";
import { HostCommandSchema } from "./commands.js";

/** Schema de validação do frame de signaling (evento + comando quando aplicável). */
export const SignalingEnvelopeSchema = z.object({
  event: z.string().min(1),
  data: z.unknown(),
});

export { z };
