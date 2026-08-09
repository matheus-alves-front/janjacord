//! JanjaCord MLS wrapper — group E2EE via mls-rs (RFC 9420), exposto a JS via wasm-bindgen.
//!
//! Modelo: a signature key de cada identidade é derivada do seed (32B) do vault local
//! (ed25519 determinístico). O estado do grupo vive num storage em memória neste módulo e é
//! serializado (base64) para o consumidor JS persistir (SQLite cifrado). Nenhum plaintext sai
//! deste módulo.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Group, MlsMessage,
};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

// ---------------------------------------------------------------------------
// storage em memória (bytes serializados do grupo; o JS persiste via export/import)
// ---------------------------------------------------------------------------

fn store() -> &'static Mutex<HashMap<Vec<u8>, Vec<u8>>> {
    static STORE: OnceLock<Mutex<HashMap<Vec<u8>, Vec<u8>>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn kp_store() -> &'static Mutex<HashMap<Vec<u8>, mls_rs_core::key_package::KeyPackageData>> {
    static KP: OnceLock<Mutex<HashMap<Vec<u8>, mls_rs_core::key_package::KeyPackageData>>> =
        OnceLock::new();
    KP.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug)]
struct StorageError(String);

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mls storage error: {}", self.0)
    }
}

impl std::error::Error for StorageError {}

impl IntoAnyError for StorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

#[derive(Clone, Default)]
struct MemStorage {
    identity: Vec<u8>,
}

impl MemStorage {
    fn new(identity: &str) -> Self {
        Self {
            identity: identity.as_bytes().to_vec(),
        }
    }

    fn key(&self, group_id: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(self.identity.len() + 1 + group_id.len());
        k.extend_from_slice(&self.identity);
        k.push(b':');
        k.extend_from_slice(group_id);
        k
    }
}

impl GroupStateStorage for MemStorage {
    type Error = StorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(store()
            .lock()
            .map_err(|_| StorageError("lock poisoned".into()))?
            .get(&self.key(group_id))
            .cloned()
            .map(Zeroizing::new))
    }

    fn epoch(
        &self,
        group_id: &[u8],
        _epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.state(group_id)
    }

    fn write(
        &mut self,
        state: GroupState,
        _epoch_inserts: Vec<EpochRecord>,
        _epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        store()
            .lock()
            .map_err(|_| StorageError("lock poisoned".into()))?
            .insert(self.key(&state.id), state.data.to_vec());
        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let _ = group_id;
        Ok(None)
    }
}

#[derive(Clone, Default)]
struct MemKpStorage;

impl mls_rs_core::key_package::KeyPackageStorage for MemKpStorage {
    type Error = StorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        kp_store()
            .lock()
            .map_err(|_| StorageError("lock poisoned".into()))?
            .remove(id);
        Ok(())
    }

    fn insert(
        &mut self,
        id: Vec<u8>,
        pkg: mls_rs_core::key_package::KeyPackageData,
    ) -> Result<(), Self::Error> {
        kp_store()
            .lock()
            .map_err(|_| StorageError("lock poisoned".into()))?
            .insert(id, pkg);
        Ok(())
    }

    fn get(
        &self,
        id: &[u8],
    ) -> Result<Option<mls_rs_core::key_package::KeyPackageData>, Self::Error> {
        Ok(kp_store()
            .lock()
            .map_err(|_| StorageError("lock poisoned".into()))?
            .get(id)
            .cloned())
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn b64e(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as E;
    use base64::Engine;
    E.encode(data)
}

fn b64d(data: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::STANDARD as E;
    use base64::Engine;
    E.decode(data).map_err(|e| e.to_string())
}

fn hexd(data: &str) -> Result<Vec<u8>, String> {
    if data.len() % 2 != 0 {
        return Err("invalid hex length".into());
    }
    (0..data.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&data[i..i + 2], 16).map_err(|e| format!("invalid hex: {e}"))
        })
        .collect()
}

fn build_client(
    seed: &[u8],
    identity_id: &str,
) -> Result<Client<impl mls_rs::client_builder::MlsConfig>, String> {
    let provider = RustCryptoProvider::default();
    let cs = provider
        .cipher_suite_provider(CIPHERSUITE)
        .ok_or_else(|| "unsupported cipher suite".to_string())?;
    // ed25519: o provider mls-rs espera o keypair de 64 bytes (seed+public), derivado do seed
    let seed32: [u8; 32] = seed
        .try_into()
        .map_err(|_| "seed must be exactly 32 bytes".to_string())?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed32);
    let secret = SignatureSecretKey::new_slice(&signing_key.to_keypair_bytes());
    let public = cs
        .signature_key_derive_public(&secret)
        .map_err(|e| format!("derive_public: {e:?}"))?;
    let credential = BasicCredential::new(identity_id.as_bytes().to_vec());
    let signing_identity = SigningIdentity::new(credential.into_credential(), public);
    Ok(Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(provider)
        .signing_identity(signing_identity, secret, CIPHERSUITE)
        .group_state_storage(MemStorage::new(identity_id))
        .key_package_repo(MemKpStorage)
        .build())
}

fn group_bytes(
    group: &Group<impl mls_rs::client_builder::MlsConfig>,
    identity_id: &str,
) -> Result<String, String> {
    let mut key = Vec::with_capacity(identity_id.len() + 1 + group.group_id().len());
    key.extend_from_slice(identity_id.as_bytes());
    key.push(b':');
    key.extend_from_slice(group.group_id().as_ref());
    let bytes = store()
        .lock()
        .map_err(|_| "storage lock poisoned".to_string())?
        .get(&key)
        .cloned()
        .ok_or_else(|| "group state not in storage".to_string())?;
    Ok(b64e(&bytes))
}

fn current_epoch(group: &Group<impl mls_rs::client_builder::MlsConfig>) -> u64 {
    group.current_epoch()
}

// ---------------------------------------------------------------------------
// implementações internas (erro String; sem wasm)
// ---------------------------------------------------------------------------

pub fn generate_key_package_inner(seed_hex: &str, identity_id: &str) -> Result<String, String> {
    let seed = hexd(seed_hex)?;
    let client = build_client(&seed, identity_id)?;
    let kp = client
        .generate_key_package_message(Default::default(), Default::default(), None)
        .map_err(|e| e.to_string())?;
    Ok(b64e(&kp.to_bytes().map_err(|e| e.to_string())?))
}

pub fn create_group_inner(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
) -> Result<String, String> {
    let seed = hexd(seed_hex)?;
    let gid = hexd(group_id_hex)?;
    let client = build_client(&seed, identity_id)?;
    let mut group = client
        .create_group_with_id(gid.clone(), Default::default(), Default::default(), None)
        .map_err(|e| e.to_string())?;
    group.write_to_storage().map_err(|e| e.to_string())?;
    let state = group_bytes(&group, identity_id)?;
    let epoch = current_epoch(&group);
    let kp = client
        .generate_key_package_message(Default::default(), Default::default(), None)
        .map_err(|e| e.to_string())?;
    let kp_b64 = b64e(&kp.to_bytes().map_err(|e| e.to_string())?);
    Ok(format!(
        r#"{{"groupStateB64":"{state}","keyPackageB64":"{kp_b64}","epoch":{epoch}}}"#
    ))
}

pub fn import_group_inner(
    identity_id: &str,
    group_id_hex: &str,
    group_state_b64: &str,
) -> Result<(), String> {
    let gid = hexd(group_id_hex)?;
    let bytes = b64d(group_state_b64)?;
    let mut key = Vec::with_capacity(identity_id.len() + 1 + gid.len());
    key.extend_from_slice(identity_id.as_bytes());
    key.push(b':');
    key.extend_from_slice(&gid);
    store()
        .lock()
        .map_err(|_| "storage lock poisoned".to_string())?
        .insert(key, bytes);
    Ok(())
}

pub fn export_group_inner(identity_id: &str, group_id_hex: &str) -> Result<String, String> {
    let gid = hexd(group_id_hex)?;
    let key = [identity_id.as_bytes().as_ref(), b":", gid.as_ref()].concat();
    let bytes = store()
        .lock()
        .map_err(|_| "storage lock poisoned".to_string())?
        .get(&key)
        .cloned()
        .ok_or_else(|| "group not found".to_string())?;
    Ok(b64e(&bytes))
}

pub fn add_member_inner(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    key_package_b64: &str,
) -> Result<String, String> {
    let seed = hexd(seed_hex)?;
    let gid = hexd(group_id_hex)?;
    let client = build_client(&seed, identity_id)?;
    let mut group = client.load_group(&gid).map_err(|e| e.to_string())?;
    let kp_bytes = b64d(key_package_b64)?;
    let kp = MlsMessage::from_bytes(&kp_bytes).map_err(|e| e.to_string())?;
    let commit = group
        .commit_builder()
        .add_member(kp)
        .map_err(|e| e.to_string())?
        .build()
        .map_err(|e| e.to_string())?;
    group.apply_pending_commit().map_err(|e| e.to_string())?;
    group.write_to_storage().map_err(|e| e.to_string())?;
    let commit_b64 = b64e(&commit.commit_message.to_bytes().map_err(|e| e.to_string())?);
    let welcome = commit
        .welcome_messages
        .first()
        .ok_or_else(|| "no welcome message".to_string())?;
    let welcome_b64 = b64e(&welcome.to_bytes().map_err(|e| e.to_string())?);
    let state = group_bytes(&group, identity_id)?;
    Ok(format!(
        r#"{{"commitB64":"{commit_b64}","welcomeB64":"{welcome_b64}","groupStateB64":"{state}"}}"#
    ))
}

pub fn remove_member_inner(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    leaf_index: u32,
) -> Result<String, String> {
    let seed = hexd(seed_hex)?;
    let gid = hexd(group_id_hex)?;
    let client = build_client(&seed, identity_id)?;
    let mut group = client.load_group(&gid).map_err(|e| e.to_string())?;
    let commit = group
        .commit_builder()
        .remove_member(leaf_index)
        .map_err(|e| e.to_string())?
        .build()
        .map_err(|e| e.to_string())?;
    group.apply_pending_commit().map_err(|e| e.to_string())?;
    group.write_to_storage().map_err(|e| e.to_string())?;
    let commit_b64 = b64e(&commit.commit_message.to_bytes().map_err(|e| e.to_string())?);
    let state = group_bytes(&group, identity_id)?;
    Ok(format!(r#"{{"commitB64":"{commit_b64}","groupStateB64":"{state}"}}"#))
}

pub fn process_commit_inner(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    commit_b64: &str,
) -> Result<(), String> {
    let seed = hexd(seed_hex)?;
    let gid = hexd(group_id_hex)?;
    let client = build_client(&seed, identity_id)?;
    let mut group = client.load_group(&gid).map_err(|e| e.to_string())?;
    let msg = MlsMessage::from_bytes(&b64d(commit_b64)?).map_err(|e| e.to_string())?;
    group.process_incoming_message(msg).map_err(|e| e.to_string())?;
    group.write_to_storage().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn join_group_inner(
    seed_hex: &str,
    identity_id: &str,
    welcome_b64: &str,
) -> Result<String, String> {
    let seed = hexd(seed_hex)?;
    let client = build_client(&seed, identity_id)?;
    let welcome = MlsMessage::from_bytes(&b64d(welcome_b64)?).map_err(|e| e.to_string())?;
    let (mut group, _info) = client.join_group(None, &welcome, None).map_err(|e| e.to_string())?;
    group.write_to_storage().map_err(|e| e.to_string())?;
    let state = group_bytes(&group, identity_id)?;
    let epoch = current_epoch(&group);
    Ok(format!(r#"{{"groupStateB64":"{state}","epoch":{epoch}}}"#))
}

pub fn encrypt_inner(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    plaintext_b64: &str,
) -> Result<String, String> {
    let seed = hexd(seed_hex)?;
    let gid = hexd(group_id_hex)?;
    let client = build_client(&seed, identity_id)?;
    let mut group = client.load_group(&gid).map_err(|e| e.to_string())?;
    let pt = b64d(plaintext_b64)?;
    let msg = group
        .encrypt_application_message(&pt, Default::default())
        .map_err(|e| e.to_string())?;
    let epoch = current_epoch(&group);
    let ct = b64e(&msg.to_bytes().map_err(|e| e.to_string())?);
    Ok(format!(r#"{{"ciphertextB64":"{ct}","epoch":{epoch}}}"#))
}

pub fn decrypt_inner(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    ciphertext_b64: &str,
) -> Result<String, String> {
    let seed = hexd(seed_hex)?;
    let gid = hexd(group_id_hex)?;
    let client = build_client(&seed, identity_id)?;
    let mut group = client.load_group(&gid).map_err(|e| e.to_string())?;
    let msg = MlsMessage::from_bytes(&b64d(ciphertext_b64)?).map_err(|e| e.to_string())?;
    match group
        .process_incoming_message(msg)
        .map_err(|e| e.to_string())?
    {
        mls_rs::group::ReceivedMessage::ApplicationMessage(app) => Ok(format!(
            r#"{{"plaintextB64":"{}","senderIndex":{}}}"#,
            b64e(&app.data()),
            app.sender_index
        )),
        other => Err(format!("unexpected message type: {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// API wasm-bindgen (wrappers)
// ---------------------------------------------------------------------------

/// Gera o key package da identidade (base64) para que outros membros possam adicioná-la.
#[wasm_bindgen]
pub fn generate_key_package(seed_hex: &str, identity_id: &str) -> Result<String, JsError> {
    generate_key_package_inner(seed_hex, identity_id).map_err(|e| JsError::new(&e))
}

/// Cria um grupo MLS com o criador como membro. Devolve JSON.
#[wasm_bindgen]
pub fn create_group(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
) -> Result<String, JsError> {
    create_group_inner(seed_hex, identity_id, group_id_hex).map_err(|e| JsError::new(&e))
}

/// Restaura um grupo previamente exportado (groupStateB64) na memória.
#[wasm_bindgen]
pub fn import_group(
    identity_id: &str,
    group_id_hex: &str,
    group_state_b64: &str,
) -> Result<(), JsError> {
    import_group_inner(identity_id, group_id_hex, group_state_b64).map_err(|e| JsError::new(&e))
}

/// Serializa o estado atual do grupo (base64) para persistência.
#[wasm_bindgen]
pub fn export_group(identity_id: &str, group_id_hex: &str) -> Result<String, JsError> {
    export_group_inner(identity_id, group_id_hex).map_err(|e| JsError::new(&e))
}

/// Adiciona membro (keyPackageB64). Devolve JSON: { commitB64, welcomeB64, groupStateB64 }.
#[wasm_bindgen]
pub fn add_member(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    key_package_b64: &str,
) -> Result<String, JsError> {
    add_member_inner(seed_hex, identity_id, group_id_hex, key_package_b64)
        .map_err(|e| JsError::new(&e))
}

/// Remove membro por leaf index. Devolve JSON: { commitB64, groupStateB64 }.
#[wasm_bindgen]
pub fn remove_member(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    leaf_index: u32,
) -> Result<String, JsError> {
    remove_member_inner(seed_hex, identity_id, group_id_hex, leaf_index)
        .map_err(|e| JsError::new(&e))
}

/// Processa commit recebido de outro membro (aplica e avança epoch).
#[wasm_bindgen]
pub fn process_commit(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    commit_b64: &str,
) -> Result<(), JsError> {
    process_commit_inner(seed_hex, identity_id, group_id_hex, commit_b64)
        .map_err(|e| JsError::new(&e))
}

/// Novo membro entra no grupo via welcome. Devolve JSON: { groupStateB64, epoch }.
#[wasm_bindgen]
pub fn join_group(
    seed_hex: &str,
    identity_id: &str,
    welcome_b64: &str,
) -> Result<String, JsError> {
    join_group_inner(seed_hex, identity_id, welcome_b64).map_err(|e| JsError::new(&e))
}

/// Cifra plaintext (base64) para o grupo. Devolve JSON: { ciphertextB64, epoch }.
#[wasm_bindgen]
pub fn encrypt(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    plaintext_b64: &str,
) -> Result<String, JsError> {
    encrypt_inner(seed_hex, identity_id, group_id_hex, plaintext_b64)
        .map_err(|e| JsError::new(&e))
}

/// Decifra mensagem do grupo. Devolve JSON: { plaintextB64, senderIndex }.
#[wasm_bindgen]
pub fn decrypt(
    seed_hex: &str,
    identity_id: &str,
    group_id_hex: &str,
    ciphertext_b64: &str,
) -> Result<String, JsError> {
    decrypt_inner(seed_hex, identity_id, group_id_hex, ciphertext_b64)
        .map_err(|e| JsError::new(&e))
}
