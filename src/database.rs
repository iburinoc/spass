extern crate rusqlite;
extern crate sodiumoxide;

use std::path::Path;

pub use rusqlite::Connection;
use rusqlite::{params, Result as RsqResult};

use crypto::Tag;
use types::{Password, User};

fn create_table(conn: &Connection, name: &str, schema: &str) {
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
            &[&name],
            |row| row.get(0),
        )
        .unwrap();
    if exists == 0 {
        conn.execute(&format!("CREATE TABLE {} {}", name, schema), params![])
            .unwrap();
    }
}

pub fn init(path: &Path) -> Connection {
    let conn = Connection::open(&path).unwrap();

    create_table(
        &conn,
        "passwords",
        "(
            id          BLOB PRIMARY KEY,
            name        BLOB NOT NULL,
            password    BLOB NOT NULL
        )",
    );
    create_table(
        &conn,
        "users",
        "(
            hash        BLOB PRIMARY KEY,
            salt        BLOB NOT NULL,
            sig         BLOB NOT NULL
        )",
    );

    conn
}

pub fn reset(conn: &mut Connection) {
    conn.execute("DELETE FROM passwords", params![]).unwrap();
    conn.execute("DELETE FROM users", params![]).unwrap();
}

pub fn get_user(conn: &Connection) -> Option<User> {
    match conn.query_row("SELECT hash, salt, sig FROM users", params![], |row| {
        let mut u: User = Default::default();
        u.hash
            .copy_from_slice(row.get::<usize, Vec<u8>>(0)?.as_ref());
        u.salt
            .copy_from_slice(row.get::<usize, Vec<u8>>(1)?.as_ref());
        u.sig
            .copy_from_slice(row.get::<usize, Vec<u8>>(2)?.as_ref());
        Ok(u)
    }) {
        Ok(user) => Some(user),
        Err(_) => None,
    }
}

pub fn set_user(conn: &mut Connection, user: &User) {
    conn.execute(
        "REPLACE INTO users VALUES (?, ?, ?)",
        params![&user.hash.as_ref(), &user.salt.as_ref(), &user.sig.as_ref()],
    )
    .unwrap();
}

fn password_from_row(row: &rusqlite::Row) -> RsqResult<Password> {
    let mut pw = Password {
        id: Default::default(),
        name: row.get(1).unwrap(),
        password: row.get(2).unwrap(),
    };
    pw.id
        .copy_from_slice(row.get::<usize, Vec<u8>>(0)?.as_ref());
    Ok(pw)
}

pub fn get_passwords(conn: &Connection) -> Vec<Password> {
    let mut stmt = conn
        .prepare("SELECT id, name, password FROM passwords ORDER BY id")
        .unwrap();
    let val = stmt
        .query_map(params![], password_from_row)
        .unwrap()
        .map(|res| res.unwrap())
        .collect();

    val
}

pub fn password_by_id(conn: &Connection, id: &Tag) -> Option<Password> {
    match conn.query_row(
        "SELECT id, name, password FROM passwords WHERE id = ?",
        params![&id.as_ref()],
        password_from_row,
    ) {
        Ok(pw) => Some(pw),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(err) => {
            panic!("{}", err.to_string());
        }
    }
}

pub fn store_password(conn: &mut Connection, pw: &Password) {
    conn.execute(
        "INSERT INTO passwords VALUES (?, ?, ?)",
        params![&pw.id.as_ref(), &pw.name, &pw.password],
    )
    .unwrap();
}

pub fn remove_password(conn: &mut Connection, id: &Tag) -> bool {
    return conn
        .execute("DELETE FROM passwords WHERE id = ?", &[&id.as_ref()])
        .unwrap()
        > 0;
}
