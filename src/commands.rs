extern crate clap;

use clap::ArgMatches;

use database;
use crypto;
use crypto::Key;
use database::Connection;
use types::{Password,User};

use super::prompt_passw;

pub fn update_verify(user: &User, key: &Key, conn: &mut Connection) {
    let nuser = User {
        hash: user.hash,
        salt: user.salt,
        sig: crypto::compute_file_sig(key, conn),
    };

    database::set_user(conn, &nuser);
}

pub fn add(args: &ArgMatches,
           user: &User,
           key: &Key,
           conn: &mut Connection) -> Result<(), String> {
    let nkey = crypto::derive_subkey(key, "NAME".as_bytes());
    let pkey = crypto::derive_subkey(key, "PASSWORD".as_bytes());

    let name = args.value_of("name").unwrap();

    let id = crypto::password_id(&nkey, name.as_ref());

    if database::password_by_id(conn, &id).is_some() {
        return Err(format!("Password with name {} already exists", name));
    };

    let pw = prompt_passw("Password to store: ").unwrap();
    if pw != prompt_passw("Confirm password: ").unwrap() {
        return Err("Passwords didn't match".into());
    };

    database::store_password(conn,
        &Password {
            id: id,
            name: crypto::encrypt_blob(&nkey, name.as_bytes()),
            password: crypto::encrypt_blob(&pkey, pw.as_bytes()),
        });

    update_verify(user, key, conn);

    Ok(())
}

pub fn ls(_args: &ArgMatches,
          _user: &User,
          key: &Key,
          conn: &mut Connection) -> Result<(), String> {
    let passwds = database::get_passwords(conn);
    let nkey = crypto::derive_subkey(key, "NAME".as_bytes());

    let mut names: Vec<String> = passwds.iter()
        .map(|pw| {
            match crypto::decrypt_blob(&nkey, pw.name.as_ref()) {
                Ok(name) => {
                    String::from_utf8_lossy(name.as_ref()).into_owned()
                },
                Err(_) => {
                    String::new()
                },
            }
        })
        .collect();
    names.sort();

    for name in names {
        println!("{}", name);
    }
    Ok(())
}
