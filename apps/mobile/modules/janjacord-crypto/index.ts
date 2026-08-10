import { NativeModules } from "react-native";

/**
 * Wrapper JS do módulo nativo JanjacordCrypto (MLS/UniFFI).
 * API espelha o binding: strings seed_hex/base64; retornos em string JSON.
 */
export const cryptoNative: {
  generateKeyPackage: (seedHex: string, identityId: string) => Promise<string>;
  createGroup: (seedHex: string, identityId: string, groupIdHex: string) => Promise<string>;
  importGroup: (identityId: string, groupIdHex: string, stateB64: string) => Promise<void>;
  exportGroup: (identityId: string, groupIdHex: string) => Promise<string>;
  addMember: (seedHex: string, identityId: string, groupIdHex: string, keyPackageB64: string) => Promise<string>;
  removeMember: (seedHex: string, identityId: string, groupIdHex: string, leafIndex: number) => Promise<string>;
  processCommit: (seedHex: string, identityId: string, groupIdHex: string, commitB64: string) => Promise<void>;
  joinGroup: (seedHex: string, identityId: string, welcomeB64: string) => Promise<string>;
  encrypt: (seedHex: string, identityId: string, groupIdHex: string, plaintextB64: string) => Promise<string>;
  decrypt: (seedHex: string, identityId: string, groupIdHex: string, ciphertextB64: string) => Promise<string>;
} = NativeModules.JanjacordCrypto;
