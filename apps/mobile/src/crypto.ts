/**
 * Wrapper do crypto para o app mobile.
 * Usa o módulo nativo (UniFFI/MLS). Se o módulo nativo não estiver disponível
 * (Expo Go), lança erro claro — o JanjaCord exige dev build (nativo).
 */
import { NativeModules } from "react-native";

const native: any = NativeModules.JanjacordCrypto;

export function hasNativeCrypto(): boolean {
  return !!native;
}

export async function assertNativeCrypto() {
  if (!native) {
    throw new Error(
      "Módulo nativo JanjacordCrypto ausente. Use um dev build (expo run:android), nunca o Expo Go."
    );
  }
  // Chama a lib de verdade (argon2 trivial) para validar o carregamento do .so no
  // arranque — se a lib falhar, o erro aparece na tela em vez de crashar no clique.
  try {
    await native.argon2id("probe", "00000000000000000000000000000000");
  } catch (e) {
    throw new Error(`Módulo nativo não carregou: ${(e as Error).message}`);
  }
}

export const mls = {
  argon2id: (password: string, saltHex: string) => native.argon2id(password, saltHex),
  generateKeyPackage: (seedHex: string, identityId: string) => native.generateKeyPackage(seedHex, identityId),
  createGroup: (seedHex: string, identityId: string, groupIdHex: string) => native.createGroup(seedHex, identityId, groupIdHex),
  importGroup: (identityId: string, groupIdHex: string, stateB64: string) => native.importGroup(identityId, groupIdHex, stateB64),
  exportGroup: (identityId: string, groupIdHex: string) => native.exportGroup(identityId, groupIdHex),
  addMember: (seedHex: string, identityId: string, groupIdHex: string, kpB64: string) => native.addMember(seedHex, identityId, groupIdHex, kpB64),
  removeMember: (seedHex: string, identityId: string, groupIdHex: string, leaf: number) => native.removeMember(seedHex, identityId, groupIdHex, leaf),
  processCommit: (seedHex: string, identityId: string, groupIdHex: string, commitB64: string) => native.processCommit(seedHex, identityId, groupIdHex, commitB64),
  joinGroup: (seedHex: string, identityId: string, welcomeB64: string) => native.joinGroup(seedHex, identityId, welcomeB64),
  encrypt: (seedHex: string, identityId: string, groupIdHex: string, ptB64: string) => native.encrypt(seedHex, identityId, groupIdHex, ptB64),
  decrypt: (seedHex: string, identityId: string, groupIdHex: string, ctB64: string) => native.decrypt(seedHex, identityId, groupIdHex, ctB64),
};
