extern crate clap;

use clap::ArgMatches;

use database;
use crypto;
use crypto::Key;
use database::Connection;
use types::{Password,User};

use super::prompt_passw;

mod generate;

fn update_verify(user: &User, key: &Key, conn: &mut Connection) {
    let nuser = User {
        hash: user.hash,
        salt: user.salt,
        sig: crypto::compute_file_sig(key, conn),
    };

    database::set_user(conn, &nuser);
}

fn get_keys(key: &Key) -> (Key, Key, Key) {
    let ikey = crypto::derive_subkey(key, "ID".as_bytes());
    let nkey = crypto::derive_subkey(key, "NAME".as_bytes());
    let pkey = crypto::derive_subkey(key, "PASSWORD".as_bytes());
    (ikey, nkey, pkey)
}

pub type CmdFn = fn(&ArgMatches, &User, &Key, &mut Connection)
    -> Result<(), String>;
pub static COMMANDS: &'static [(&str, CmdFn)] = &[
    ("add", add),
    ("chpw", chpw),
    ("ls", ls),
    ("gen", gen),
    ("get", get),
    ("rm", rm),
];



pub fn add(args: &ArgMatches,
           user: &User,
           key: &Key,
           conn: &mut Connection) -> Result<(), String> {
    let (ikey, nkey, pkey) = get_keys(key);

    let name = args.value_of("name").unwrap();

    let id = crypto::password_id(&ikey, name.as_ref());

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

    println!("{} added", name);

    Ok(())
}

pub fn chpw(_args: &ArgMatches,
            _user: &User,
            key: &Key,
            conn: &mut Connection) -> Result<(), String> {
    let (_, nkey, pkey) = get_keys(key);

    let pw = prompt_passw("New master password: ").unwrap();
    if pw != prompt_passw("Confirm password: ").unwrap() {
        return Err("Passwords didn't match".into());
    };

    // TODO figure out borrow issue here
    //let mut tx = conn.transaction().unwrap();
    conn.execute("BEGIN", &[]).unwrap();
    let (mut nuser, newkey) = crypto::create_user(&pw);
    let (nikey, nnkey, npkey) = get_keys(&newkey);

    let passwords = database::get_passwords(conn);
    database::reset(conn);
    for passw in passwords {
        use std::str;
        let name = crypto::decrypt_blob(&nkey, passw.name.as_ref()).unwrap();
        let pw = crypto::decrypt_blob(&pkey, passw.password.as_ref()).unwrap();
        let npassw = Password {
            id: crypto::password_id(&nikey,
                                    str::from_utf8(name.as_ref()).unwrap()),
            name: crypto::encrypt_blob(&nnkey, name.as_ref()),
            password: crypto::encrypt_blob(&npkey, pw.as_ref()),
        };
        database::store_password(conn, &npassw);
    }
    nuser.sig = crypto::compute_file_sig(&newkey, conn);
    database::set_user(conn, &nuser);
    //tx.commit().unwrap();
    conn.execute("COMMIT", &[]).unwrap();

    println!("Password successfully changed");

    Ok(())
}

pub fn gen(args: &ArgMatches,
           user: &User,
           key: &Key,
           conn: &mut Connection) -> Result<(), String> {
    let (ikey, nkey, pkey) = get_keys(key);

    let name = args.value_of("name").unwrap();

    let id = crypto::password_id(&ikey, name.as_ref());

    if database::password_by_id(conn, &id).is_some() {
        return Err(format!("Password with name {} already exists", name));
    };

    let len = value_t!(args.value_of("length"), usize).unwrap();
    let opts = generate::PasswCharset {
        lower: args.value_of("lower").unwrap() == "y",
        upper: args.value_of("upper").unwrap() == "y",
        digit: args.value_of("digit").unwrap() == "y",
        sym: args.value_of("sym").unwrap() == "y",
    };

    let (pw, ent) = generate::generate(len, &opts)?;

    let strct = Password {
        id: id,
        name: crypto::encrypt_blob(&nkey, name.as_ref()),
        password: crypto::encrypt_blob(&pkey, pw.as_ref()),
    };

    database::store_password(conn, &strct);
    update_verify(user, key, conn);

    println!("{}", pw);
    eprintln!("Password generated with {} bits of entropy", ent);

    Ok(())
}

pub fn get(args: &ArgMatches,
           _user: &User,
           key: &Key,
           conn: &mut Connection) -> Result<(), String> {
    let (ikey, _, pkey) = get_keys(key);

    let name = args.value_of("name").unwrap();

    let id = crypto::password_id(&ikey, name.as_ref());

    match database::password_by_id(conn, &id) {
        Some(pw) => match crypto::decrypt_blob(&pkey, pw.password.as_ref()) {
            Ok(bytes) => {
                let passw = String::from_utf8_lossy(bytes.as_ref());
                println!("{}", passw);
                Ok(())
            },
            Err(_) => Err(format!("Failed to decrypt password {}", name)),
        },
        None => Err(format!("Password {} not found", name))
    }
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

pub fn rm(args: &ArgMatches,
          user: &User,
          key: &Key,
          conn: &mut Connection) -> Result<(), String> {
    let (ikey, _, _) = get_keys(key);

    let name = args.value_of("name").unwrap();

    let id = crypto::password_id(&ikey, name.as_ref());

    if !database::remove_password(conn, &id) {
        return Err(format!("Password {} not found", name));
    }

    update_verify(user, key, conn);

    Ok(())
}
