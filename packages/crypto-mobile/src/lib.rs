//! Bindings nativos (UniFFI) do wrapper MLS para React Native (Kotlin/Swift).
//! Reusa a lógica do crate `janjacord-mls` (mesma do desktop WASM) — zero duplicação.
//! O app mobile chama estas funções via TurboModule.

uniffi::setup_scaffolding!();

/// Erro exposto ao Kotlin/Swift (uniffi exige tipo de erro próprio, não String).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MlsError {
    #[error("{0}")]
    Message(String),
}

impl From<String> for MlsError {
    fn from(s: String) -> Self {
        MlsError::Message(s)
    }
}

macro_rules! mls_export {
    ($name:ident, $($arg:ident: $ty:ty),*) => {
        #[uniffi::export]
        pub fn $name($($arg: $ty),*) -> Result<String, MlsError> {
            janjacord_mls::$name($($arg),*).map_err(MlsError::Message)
        }
    };
}

#[uniffi::export]
pub fn generate_key_package(seed_hex: String, identity_id: String) -> Result<String, MlsError> {
    janjacord_mls::generate_key_package_inner(&seed_hex, &identity_id).map_err(MlsError::Message)
}

#[uniffi::export]
pub fn create_group(seed_hex: String, identity_id: String, group_id_hex: String) -> Result<String, MlsError> {
    janjacord_mls::create_group_inner(&seed_hex, &identity_id, &group_id_hex).map_err(MlsError::Message)
}

#[uniffi::export]
pub fn import_group(identity_id: String, group_id_hex: String, group_state_b64: String) -> Result<(), MlsError> {
    janjacord_mls::import_group_inner(&identity_id, &group_id_hex, &group_state_b64).map_err(MlsError::Message)
}

#[uniffi::export]
pub fn export_group(identity_id: String, group_id_hex: String) -> Result<String, MlsError> {
    janjacord_mls::export_group_inner(&identity_id, &group_id_hex).map_err(MlsError::Message)
}

#[uniffi::export]
pub fn add_member(
    seed_hex: String,
    identity_id: String,
    group_id_hex: String,
    key_package_b64: String,
) -> Result<String, MlsError> {
    janjacord_mls::add_member_inner(&seed_hex, &identity_id, &group_id_hex, &key_package_b64)
        .map_err(MlsError::Message)
}

#[uniffi::export]
pub fn remove_member(
    seed_hex: String,
    identity_id: String,
    group_id_hex: String,
    leaf_index: u32,
) -> Result<String, MlsError> {
    janjacord_mls::remove_member_inner(&seed_hex, &identity_id, &group_id_hex, leaf_index).map_err(MlsError::Message)
}

#[uniffi::export]
pub fn process_commit(
    seed_hex: String,
    identity_id: String,
    group_id_hex: String,
    commit_b64: String,
) -> Result<(), MlsError> {
    janjacord_mls::process_commit_inner(&seed_hex, &identity_id, &group_id_hex, &commit_b64).map_err(MlsError::Message)
}

#[uniffi::export]
pub fn join_group(seed_hex: String, identity_id: String, welcome_b64: String) -> Result<String, MlsError> {
    janjacord_mls::join_group_inner(&seed_hex, &identity_id, &welcome_b64).map_err(MlsError::Message)
}

#[uniffi::export]
pub fn encrypt(
    seed_hex: String,
    identity_id: String,
    group_id_hex: String,
    plaintext_b64: String,
) -> Result<String, MlsError> {
    janjacord_mls::encrypt_inner(&seed_hex, &identity_id, &group_id_hex, &plaintext_b64).map_err(MlsError::Message)
}

#[uniffi::export]
pub fn decrypt(
    seed_hex: String,
    identity_id: String,
    group_id_hex: String,
    ciphertext_b64: String,
) -> Result<String, MlsError> {
    janjacord_mls::decrypt_inner(&seed_hex, &identity_id, &group_id_hex, &ciphertext_b64).map_err(MlsError::Message)
}
