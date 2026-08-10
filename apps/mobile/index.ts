/**
 * Entry do JanjaCord Mobile.
 * Polyfill do Buffer (Hermes não tem global.Buffer) + registro do App real.
 */
import { Buffer } from "buffer";
(globalThis as any).Buffer = Buffer;

import { registerRootComponent } from "expo";
import App from "./src/App";

registerRootComponent(App);
