extern crate rusqlite;
extern crate sodiumoxide;

use std::path::Path;

pub use rusqlite::Connection;

use types::{User, Password};

fn create_table(conn: &Connection, name: &str, schema: &str) {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
        &[&name],
        |row| { row.get(0) } ).unwrap();
    if exists == 0 {
        conn.execute(
            &format!("CREATE TABLE {} {}", name, schema), &[]).unwrap();
    }
}

pub fn init(path: &Path) -> Connection {
    let conn = Connection::open(&path).unwrap();

    create_table(&conn, "passwords", "(
            id          BLOB PRIMARY KEY,
            name        BLOB NOT NULL,
            password    BLOB NOT NULL
        )");
    create_table(&conn, "users", "(
            hash        BLOB NOT NULL,
            salt        BLOB NOT NULL,
            sig         BLOB NOT NULL
        )");

    conn
}

pub fn reset(conn: &mut Connection) {
    conn.execute("DELETE FROM passwords", &[]).unwrap();
    conn.execute("DELETE FROM users", &[]).unwrap();
}

pub fn get_user(conn: &Connection) -> Option<User> {
    match conn.query_row(
            "SELECT hash, salt, sig FROM users",
            &[],
            |row| {
                let mut u: User = Default::default();
                u.hash.copy_from_slice(row.get::<i32, Vec<u8>>(0).as_ref());
                u.salt.copy_from_slice(row.get::<i32, Vec<u8>>(1).as_ref());
                u.sig.copy_from_slice(row.get::<i32, Vec<u8>>(2).as_ref());
                u
            }) {
        Ok(user) => Some(user),
        Err(_) => None,
    }
}

pub fn set_user(conn: &mut Connection, user: &User) {
    conn.execute(
            "REPLACE INTO users VALUES (?, ?, ?)",
            &[&user.hash.as_ref(), &user.salt.as_ref(), &user.sig.as_ref()])
        .unwrap();
}

pub fn get_passwords(conn: &Connection) -> Vec<Password> {
    let mut stmt = conn
        .prepare("SELECT id, name, password FROM passwords ORDER BY id")
        .unwrap();
    let val = stmt.query_map(&[], |row| {
        let mut pw = Password {
            id: Default::default(),
            name: row.get(1),
            password: row.get(2)
        };
        pw.id.copy_from_slice(row.get::<i32, Vec<u8>>(0).as_ref());
        pw
    }).unwrap()
      .map(|res| res.unwrap())
      .collect();

	val
}
