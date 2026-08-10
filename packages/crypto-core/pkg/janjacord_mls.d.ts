/* tslint:disable */
/* eslint-disable */

/**
 * Adiciona membro (keyPackageB64). Devolve JSON: { commitB64, welcomeB64, groupStateB64 }.
 */
export function add_member(seed_hex: string, identity_id: string, group_id_hex: string, key_package_b64: string): string;

/**
 * Cria um grupo MLS com o criador como membro. Devolve JSON.
 */
export function create_group(seed_hex: string, identity_id: string, group_id_hex: string): string;

/**
 * Decifra mensagem do grupo. Devolve JSON: { plaintextB64, senderIndex }.
 */
export function decrypt(seed_hex: string, identity_id: string, group_id_hex: string, ciphertext_b64: string): string;

/**
 * Cifra plaintext (base64) para o grupo. Devolve JSON: { ciphertextB64, epoch }.
 */
export function encrypt(seed_hex: string, identity_id: string, group_id_hex: string, plaintext_b64: string): string;

/**
 * Serializa o estado atual do grupo (base64) para persistência.
 */
export function export_group(identity_id: string, group_id_hex: string): string;

/**
 * Gera o key package da identidade (base64) para que outros membros possam adicioná-la.
 */
export function generate_key_package(seed_hex: string, identity_id: string): string;

/**
 * Restaura um grupo previamente exportado (groupStateB64) na memória.
 */
export function import_group(identity_id: string, group_id_hex: string, group_state_b64: string): void;

/**
 * Novo membro entra no grupo via welcome. Devolve JSON: { groupStateB64, epoch }.
 */
export function join_group(seed_hex: string, identity_id: string, welcome_b64: string): string;

/**
 * Processa commit recebido de outro membro (aplica e avança epoch).
 */
export function process_commit(seed_hex: string, identity_id: string, group_id_hex: string, commit_b64: string): void;

/**
 * Remove membro por leaf index. Devolve JSON: { commitB64, groupStateB64 }.
 */
export function remove_member(seed_hex: string, identity_id: string, group_id_hex: string, leaf_index: number): string;
