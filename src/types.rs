extern crate sodiumoxide;

use super::crypto;
use sodiumoxide::crypto::{auth, pwhash};

#[derive(Default, Debug)]
pub struct User {
    pub hash: [u8; crypto::HASHBYTES],
    pub salt: [u8; pwhash::SALTBYTES],
    pub sig: [u8; auth::TAGBYTES],
}

#[derive(Default, Debug)]
pub struct Password {
    pub id: [u8; auth::TAGBYTES],
    pub name: Vec<u8>,
    pub password: Vec<u8>,
}
