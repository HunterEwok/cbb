// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Blind credentials on the format's vectors, server cards and faces.

use std::collections::BTreeMap;
use std::path::PathBuf;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use serde_json::Value as Json;

use super::alias::{self, Face};
use super::card::{self, Card};
use super::credential::{self, Chain, Credential};
use crate::certs::sha256;
use crate::format::{Alg, Key, Rule};
use crate::identity::ExternalKey;

fn load(name: &str) -> Json {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/format").join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct K(SigningKey);

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> crate::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn k(name: &str) -> K {
    K(SigningKey::from_slice(&sha256(name.as_bytes())).unwrap())
}

#[test]
fn credentials_of_the_vectors() {
    let v = load("credentials.json");
    let mut read = Vec::new();
    for t in v["take"].as_array().unwrap() {
        let c =
            Credential::read(&unhex(t["envelope"].as_str().unwrap())).unwrap_or_else(|r| panic!("{}: {r}", t["name"]));
        assert_eq!(hex(&c.id), t["id"].as_str().unwrap());
        read.push(c);
    }
    for r in v["refuse"].as_array().unwrap() {
        let got = Credential::read(&unhex(r["envelope"].as_str().unwrap()));
        assert_eq!(got.err().map(Rule::name), r["rule"].as_str(), "{}", r["name"]);
    }
    let (period, hubs, members) = (&read[0], &read[2], &read[3]);
    assert_eq!(credential::check_chain(period, hubs, Some(members)), Ok(()));
    assert_eq!(credential::check_chain(period, members, None), Err(Chain::Hubs));
    assert_eq!(credential::check_chain(&read[1], hubs, None), Err(Chain::Period));
    // A relay with a fixed list takes the period of a listed group by its root.
    let root = period.signer.clone();
    let gid = Key::new(Alg::Es256, &root).device_id().0;
    assert!(period.period_of_listed_group(&root, &[gid]));
    assert!(!period.period_of_listed_group(&root, &[[0; 16]]));
    assert!(
        !read[1].period_of_listed_group(&read[1].signer, &[read[1].group]),
        "a device's server credential is no period"
    );
    assert!(period.live(period.expires_ms - 1) && !period.live(period.expires_ms));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

#[test]
fn padded_lists() {
    let one = [[7u8; 32]];
    assert_eq!(credential::pad(&one, credential::LENGTHS_HUBS).unwrap().len(), 4);
    assert_eq!(credential::pad(&[[1; 32]; 5], credential::LENGTHS_HUBS).unwrap().len(), 8);
    assert!(credential::pad(&[[1; 32]; 17], credential::LENGTHS_HUBS).is_none());
    assert_eq!(credential::pad(&one, credential::LENGTHS_HUBS).unwrap()[0], one[0], "real entries first");
}

fn card() -> Card {
    Card {
        operator: k("operator").public(),
        version: 1,
        expires_ms: 1_800_000_000_000,
        name: "a forwarder in Europe".into(),
        endpoints: vec!["fwd.example.org:443".into(), "192.0.2.7:443".into()],
        keys: vec![k("server tls").public()],
        kinds: card::KIND_FORWARDER,
        paths: card::PATH_WIREGUARD | card::PATH_VLESS,
    }
}

#[test]
fn a_server_card() {
    let c = card();
    let env = c.sign(&k("operator")).unwrap();
    let got = Card::read(&env).unwrap();
    assert_eq!(got, c);
    assert_eq!(got.pins(), vec![Key::new(Alg::Es256, &k("server tls").public()).hash()]);

    // Signed by someone else than the operator it names.
    let forged = c.sign(&k("someone")).unwrap();
    assert_eq!(Card::read(&forged).err(), Some(Rule::SIG_VERIFY));

    // Rows.
    for (f, rule) in [
        (Box::new(|c: &mut Card| c.name = String::new()) as Box<dyn Fn(&mut Card)>, card::RULE_NAME),
        (Box::new(|c: &mut Card| c.endpoints = vec![]), card::RULE_ENDPOINTS),
        (Box::new(|c: &mut Card| c.endpoints = vec!["no port".into()]), card::RULE_ENDPOINTS),
        (Box::new(|c: &mut Card| c.endpoints = vec!["a.example:443".into(); 9]), card::RULE_ENDPOINTS),
        (Box::new(|c: &mut Card| c.keys = vec![]), card::RULE_KEYS),
        (Box::new(|c: &mut Card| c.keys = vec![vec![4; 65]]), card::RULE_KEYS),
        (Box::new(|c: &mut Card| c.kinds = 4), card::RULE_KINDS),
        (Box::new(|c: &mut Card| c.paths = 8), card::RULE_PATHS),
    ] {
        let mut bad = card();
        f(&mut bad);
        assert_eq!(Card::read(&bad.sign(&k("operator")).unwrap()).err(), Some(rule));
    }

    // A later version of the same operator replaces it; another operator's does not.
    let mut next = card();
    next.version = 2;
    assert!(c.replaced_by(&next));
    next.operator = k("someone").public();
    assert!(!c.replaced_by(&next));
}

#[test]
fn each_server_its_own_face() {
    let mut faces = BTreeMap::new();
    for (i, s) in ["server a", "server b", "server c"].iter().enumerate() {
        faces.insert(Key::new(Alg::Es256, &k(s).public()).hash(), alias::new_face(k(&format!("period {i}")).public()));
    }
    assert!(alias::distinct(&faces));
    let first = faces.values().next().unwrap().clone();
    faces.insert(
        Key::new(Alg::Es256, &k("server d").public()).hash(),
        Face { tag: [9; 16], period_key: first.period_key },
    );
    assert!(!alias::distinct(&faces), "a period key shown to two servers links them");

    let v = load("credentials.json");
    let creds: Vec<Credential> = v["take"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| Credential::read(&unhex(t["envelope"].as_str().unwrap())).unwrap())
        .collect();
    assert!(alias::linkable(&creds[0], &creds[2]), "one period: the same tag and key");
}
