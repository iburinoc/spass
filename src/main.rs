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
    let mut conn = database::init("test");

    do_setup(&mut conn);

    do_test(&conn);
}

fn do_setup(conn: &mut database::Connection) {
    let pw = prompt_passw("Master password: ").unwrap();
    let (mut user, key) = crypto::create_user(&pw);

    user.sig = crypto::compute_file_sig(&key, conn);

    println!("{:?} {:?} {:?}", user, pw, key);

    database::set_user(conn, &user);
}

fn do_test(conn: &database::Connection) {
    let user = database::get_user(&conn);
    let pw = prompt_passw("Master password: ").unwrap();
    let key = crypto::get_key(&user, &pw);
    println!("{:?} {:?} {:?}", user, pw, key);
    println!("verify: {:?}", crypto::verify_file(&user, &key, conn));
}
