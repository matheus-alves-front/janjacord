use janjacord_mls::*;

fn main() {
    let seed_a = "a".repeat(64);
    let seed_b = "b".repeat(64);
    let gid = hex::encode("group-1");

    let created = serde_json::from_str::<serde_json::Value>(&create_group_inner(&seed_a, "alice", &gid).unwrap()).unwrap();
    println!("create_group: epoch={} stateLen={}", created["epoch"], created["groupStateB64"].as_str().unwrap().len());

    let kp = generate_key_package_inner(&seed_b, "bob").unwrap();
    println!("bob kp len={}", kp.len());

    let added = serde_json::from_str::<serde_json::Value>(&add_member_inner(&seed_a, "alice", &gid, &kp).unwrap()).unwrap();
    println!("add_member: commitLen={} welcomeLen={}", added["commitB64"].as_str().unwrap().len(), added["welcomeB64"].as_str().unwrap().len());

    let joined = serde_json::from_str::<serde_json::Value>(&join_group_inner(&seed_b, "bob", added["welcomeB64"].as_str().unwrap()).unwrap()).unwrap();
    println!("join_group: epoch={}", joined["epoch"]);

    let msg = serde_json::from_str::<serde_json::Value>(&encrypt_inner(&seed_a, "alice", &gid, &b64e(b"ola janjacord")).unwrap()).unwrap();
    println!("encrypt: epoch={} ctLen={}", msg["epoch"], msg["ciphertextB64"].as_str().unwrap().len());

    let dec = serde_json::from_str::<serde_json::Value>(&decrypt_inner(&seed_b, "bob", &gid, msg["ciphertextB64"].as_str().unwrap()).unwrap()).unwrap();
    println!("decrypt: senderIndex={} plaintext={}", dec["senderIndex"], String::from_utf8(b64d(dec["plaintextB64"].as_str().unwrap()).unwrap()).unwrap());

    let exported = export_group_inner("alice", &gid).unwrap();
    import_group_inner("alice", &gid, &exported).unwrap();
    let dec2 = serde_json::from_str::<serde_json::Value>(&decrypt_inner(&seed_b, "bob", &gid, msg["ciphertextB64"].as_str().unwrap()).unwrap()).unwrap();
    println!("re-decrypt apos import: {}", String::from_utf8(b64d(dec2["plaintextB64"].as_str().unwrap()).unwrap()).unwrap());

    let removed = serde_json::from_str::<serde_json::Value>(&remove_member_inner(&seed_a, "alice", &gid, 1).unwrap()).unwrap();
    println!("remove_member: commitLen={}", removed["commitB64"].as_str().unwrap().len());

    println!("SMOKE NATIVO OK");
}

fn b64e(d: &[u8]) -> String { use base64::Engine; base64::engine::general_purpose::STANDARD.encode(d) }
fn b64d(d: &str) -> Result<Vec<u8>, String> { use base64::Engine; base64::engine::general_purpose::STANDARD.decode(d).map_err(|e| e.to_string()) }
