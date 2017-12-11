extern crate rpassword;
extern crate rusqlite;
extern crate sodiumoxide;

use rpassword::prompt_password_stderr as prompt_passw;

mod crypto;
mod database;
mod types;

pub use types::*;

fn main() {
    crypto::init();
    let conn = database::init("test");

    do_setup(&conn);

    do_test(&conn);
}

fn do_setup(conn: &database::Connection) {
    let pw = prompt_passw("Master password: ").unwrap();
    let (user, key) = crypto::create_user(&pw);

    println!("{:?} {:?} {:?}", user, pw, key);
}

fn do_test(conn: &database::Connection) {
    let user = database::get_user(&conn);
    let pw = prompt_passw("Master password: ").unwrap();
    let key = crypto::get_key(&user, &pw);
    println!("{:?} {:?} {:?}", user, pw, key);
}
