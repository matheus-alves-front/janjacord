const { contextBridge, ipcRenderer } = require("electron");

/** API mínima exposta ao renderer (contextIsolation + sandbox; nada de ipcRenderer cru). */
contextBridge.exposeInMainWorld("janjacord", {
  identityStatus: () => ipcRenderer.invoke("identity.status"),
  identityCreate: (nickname, password) => ipcRenderer.invoke("identity.create", { nickname, password }),
  identityUnlock: (password) => ipcRenderer.invoke("identity.unlock", { password }),
  identityRestore: (recoveryKey, nickname, newPassword) =>
    ipcRenderer.invoke("identity.restore", { recoveryKey, nickname, newPassword }),
  serverCreate: () => ipcRenderer.invoke("server.create"),
  serverJoin: (hostUrl, inviteKey) => ipcRenderer.invoke("server.join", { hostUrl, inviteKey }),
  serverState: () => ipcRenderer.invoke("server.state"),
  sendMessage: (channelId, text) => ipcRenderer.invoke("message.send", { channelId, text }),
  inviteCreate: () => ipcRenderer.invoke("invite.create"),
  hostUrl: () => ipcRenderer.invoke("host.url"),
  linkingCreate: () => ipcRenderer.invoke("linking.create"),
  memberAction: (identityId, action) => ipcRenderer.invoke("member.action", { identityId, action }),
  createRole: (name, level, permissions) => ipcRenderer.invoke("role.create", { name, level, permissions }),
  assignRole: (memberIdentityId, roleId) => ipcRenderer.invoke("role.assign", { memberIdentityId, roleId }),
  updateServerConfig: (config) => ipcRenderer.invoke("server.updateConfig", { config }),
  listInvites: () => ipcRenderer.invoke("invite.list"),
  revokeInvite: (inviteId) => ipcRenderer.invoke("invite.revoke", { inviteId }),
  attachmentSend: (channelId, name, mimeType, dataB64) => ipcRenderer.invoke("attachment.send", { channelId, name, mimeType, dataB64 }),
  attachmentDownload: (assetId) => ipcRenderer.invoke("attachment.download", { assetId }),
  attachmentSave: (assetId, name) => ipcRenderer.invoke("attachment.save", { assetId, name }),
  callJoin: (channelId) => ipcRenderer.invoke("call.join", { channelId }),
  callLeave: (channelId) => ipcRenderer.invoke("call.leave", { channelId }),
  callSignal: (channelId, to, payload) => ipcRenderer.invoke("call.signal", { channelId, to, payload }),
  on: (channel, cb) => {
    ipcRenderer.on(channel, (_e, data) => cb(data));
  },
});
