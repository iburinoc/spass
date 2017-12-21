extern crate sodiumoxide;

use sodiumoxide::crypto::{auth, pwhash, secretbox};
use sodiumoxide::randombytes;
use sodiumoxide::utils;

use types::User;
use database::Connection;
use database;

pub const KEYBYTES: usize = 32;
pub const HASHBYTES: usize = 32;
pub const DERIVBYTES: usize = KEYBYTES + HASHBYTES;

pub type Key = [u8; KEYBYTES];
pub type Hash = [u8; HASHBYTES];
pub type Tag = [u8; auth::TAGBYTES];

pub use sodiumoxide::init;

pub fn random(max: u64) -> u64 {
    if max != 0 {
        let mut ret = max;
        while ret == max {
            use std::u64;
            let val = randombytes::randombytes(8).iter()
                .fold(0u64, |a, b| 0x100u64 * a + (*b as u64));
            if u64::MAX / max > val / max {
                ret = val % max;
            }
        };
        ret
    } else {
        0u64
    }
}

fn derive_key(key: &mut Key, hash: &mut Hash,
              pw: &str, salt: &[u8; pwhash::SALTBYTES]) {
    let mut res = [0u8; DERIVBYTES];
    pwhash::derive_key(
        &mut res,
        pw.as_bytes(),
        &pwhash::Salt::from_slice(salt).unwrap(),
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE).unwrap();

    key.copy_from_slice(&res[0 .. KEYBYTES]);
    hash.copy_from_slice(&res[KEYBYTES .. DERIVBYTES]);
}

pub fn get_key(user: &User, pw: &str) -> Key {
    let mut k: Key = Default::default();
    let mut h: Hash = Default::default();

    derive_key(&mut k, &mut h, pw, &user.salt);
    if !utils::memcmp(&h, &user.hash) {
        panic!("Password incorrect");
    }

    k
}

pub fn derive_subkey(k: &Key, id: &[u8]) -> Key {
    let auth::Tag(sk) = auth::authenticate(id,
            &auth::Key::from_slice(k).unwrap());
    sk
}

pub fn create_user(pw: &str) -> (User, Key) {
    let mut u: User = Default::default();

    let pwhash::Salt(salt) = pwhash::gen_salt();
    u.salt.copy_from_slice(&salt);

    let mut k: Key = Default::default();
    derive_key(&mut k, &mut u.hash, pw, &salt);

    (u, k)
}

pub fn compute_file_sig(key: &Key, conn: &Connection) -> [u8; auth::TAGBYTES] {
    let skey = derive_subkey(key, "VERIFY".as_bytes());

    let mut state = auth::State::init(&skey);
    let passwords = database::get_passwords(conn);
    for passw in passwords {
        state.update(&passw.id);
        state.update(passw.name.as_slice());
        state.update(passw.password.as_slice());
    }

    let auth::Tag(digest) = state.finalize();

    digest
}

pub fn verify_file(user: &User, key: &Key, conn: &Connection) -> bool {
    let file_sig = compute_file_sig(key, conn);
    sodiumoxide::utils::memcmp(&user.sig, &file_sig)
}

pub fn encrypt_blob(k: &Key, m: &[u8]) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let mut res = nonce.as_ref().to_vec();
    let key = secretbox::Key::from_slice(k).unwrap();
    res.append(&mut secretbox::seal(m, &nonce, &key));
    res
}

pub fn decrypt_blob(k: &Key, c: &[u8]) -> Result<Vec<u8>, ()> {
    let nonce = secretbox::Nonce::from_slice(&c[ .. secretbox::NONCEBYTES])
        .unwrap();
    let key = secretbox::Key::from_slice(k).unwrap();
    secretbox::open(&c[secretbox::NONCEBYTES .. ], &nonce, &key)
}

pub fn password_id(namekey: &Key, name: &str) -> Tag {
    let key = auth::Key::from_slice(namekey).unwrap();
    let auth::Tag(tag) = auth::authenticate(name.as_bytes(), &key);
    tag
}
