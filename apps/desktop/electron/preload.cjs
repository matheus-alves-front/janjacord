const { contextBridge, ipcRenderer } = require("electron");

const pendingLegacyConfirmations = new Map();

async function serverJoin(hostUrl, inviteKey, allowLegacyTrust = false) {
  const key = `${hostUrl}\u0000${inviteKey}`;
  const pending = allowLegacyTrust ? pendingLegacyConfirmations.get(key) : undefined;
  const result = await ipcRenderer.invoke("server.join", {
    hostUrl,
    inviteKey,
    allowLegacyTrust,
    ...(pending ? {
      legacyConfirmationToken: pending.confirmationToken,
      expectedHostPublicKey: pending.hostPublicKey,
      expectedHostFingerprint: pending.fingerprint,
    } : {}),
  });
  const data = result?.error?.data;
  if (result?.error?.code === "legacy_confirmation_required" && data
    && typeof data.confirmationToken === "string" && typeof data.hostPublicKey === "string"
    && typeof data.fingerprint === "string") {
    pendingLegacyConfirmations.set(key, data);
  } else if (result?.ok || allowLegacyTrust) {
    pendingLegacyConfirmations.delete(key);
  }
  return result;
}

/** API mínima exposta ao renderer (contextIsolation + sandbox; nada de ipcRenderer cru). */
contextBridge.exposeInMainWorld("janjacord", {
  identityStatus: () => ipcRenderer.invoke("identity.status"),
  identityCreate: (nickname, password) => ipcRenderer.invoke("identity.create", { nickname, password }),
  identityUnlock: (password) => ipcRenderer.invoke("identity.unlock", { password }),
  identityRestore: (recoveryKey, nickname, newPassword) =>
    ipcRenderer.invoke("identity.restore", { recoveryKey, nickname, newPassword }),
  serverCreate: () => ipcRenderer.invoke("server.create"),
  serverJoin,
  connectivityStatus: () => ipcRenderer.invoke("connectivity.status"),
  connectivityTurnSet: (keyId, apiToken) => ipcRenderer.invoke("connectivity.turn.set", { keyId, apiToken }),
  connectivityTurnClear: () => ipcRenderer.invoke("connectivity.turn.clear"),
  connectivityProviders: () => ipcRenderer.invoke("connectivity.providers"),
  connectivityProviderStart: (provider, config) => ipcRenderer.invoke("connectivity.provider.start", { provider, config }),
  connectivityProviderStop: () => ipcRenderer.invoke("connectivity.provider.stop"),
  iceConfiguration: () => ipcRenderer.invoke("connectivity.ice-config"),
  bridgeAdd: (pairingCode) => ipcRenderer.invoke("connectivity.bridge.add", { pairingCode }),
  bridgeRemove: (bridgeId) => ipcRenderer.invoke("connectivity.bridge.remove", { bridgeId }),
  setHostingAutostart: (enabled) => ipcRenderer.invoke("hosting.autostart", { enabled }),
  registerHostCandidate: () => ipcRenderer.invoke("hosting.candidate.register"),
  listHostGrants: () => ipcRenderer.invoke("hosting.grant.list"),
  authorizeHostCandidate: (subjectIdentityId, candidateId) => ipcRenderer.invoke("hosting.grant.authorize", { subjectIdentityId, candidateId }),
  revokeHostGrant: (grantId) => ipcRenderer.invoke("hosting.grant.revoke", { grantId }),
  acceptHostGrant: (grant) => ipcRenderer.invoke("hosting.grant.accept", { grant }),
  serverState: () => ipcRenderer.invoke("server.state"),
  sendMessage: (channelId, text) => ipcRenderer.invoke("message.send", { channelId, text }),
  inviteCreate: () => ipcRenderer.invoke("invite.create"),
  clipboardClearIfEquals: (text) => ipcRenderer.invoke("clipboard.clearIfEquals", { text }),
  channelCreate: (channelType, name) => ipcRenderer.invoke("channel.create", { channelType, name }),
  hostUrl: () => ipcRenderer.invoke("host.url"),
  memberAction: (identityId, action) => ipcRenderer.invoke("member.action", { identityId, action }),
  createRole: (name, level, permissions) => ipcRenderer.invoke("role.create", { name, level, permissions }),
  assignRole: (memberIdentityId, roleId) => ipcRenderer.invoke("role.assign", { memberIdentityId, roleId }),
  updateServerConfig: (config) => ipcRenderer.invoke("server.updateConfig", { config }),
  listInvites: () => ipcRenderer.invoke("invite.list"),
  revokeInvite: (inviteId) => ipcRenderer.invoke("invite.revoke", { inviteId }),
  attachmentSend: (channelId, name, mimeType, dataB64) => ipcRenderer.invoke("attachment.send", { channelId, name, mimeType, dataB64 }),
  attachmentSave: (assetId, name) => ipcRenderer.invoke("attachment.save", { assetId, name }),
  callJoin: (channelId) => ipcRenderer.invoke("call.join", { channelId }),
  callLeave: (channelId) => ipcRenderer.invoke("call.leave", { channelId }),
  callSignal: (channelId, to, payload) => ipcRenderer.invoke("call.signal", { channelId, to, payload }),
  on: (channel, cb) => {
    ipcRenderer.on(channel, (_e, data) => cb(data));
  },
});
