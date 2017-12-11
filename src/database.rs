extern crate rusqlite;
extern crate sodiumoxide;

pub use rusqlite::Connection;

use types::{User, Password};

fn create_table(conn: &Connection, name: &str, schema: &str) {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
        &[&name],
        |row| { row.get(0) } ).unwrap();
    if exists == 0 {
        let res = conn.execute(
            &format!("CREATE TABLE {} {}", name, schema), &[]).unwrap();
        println!("{:?}", res);
    }
}

pub fn init(path: &str) -> Connection {
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

pub fn get_user(conn: &Connection) -> User {
    conn.query_row(
        "SELECT hash, salt, sig FROM users",
        &[],
        |row| {
            let mut u: User = Default::default();
            u.hash.copy_from_slice(row.get::<i32, Vec<u8>>(0).as_ref());
            u.salt.copy_from_slice(row.get::<i32, Vec<u8>>(1).as_ref());
            u.sig.copy_from_slice(row.get::<i32, Vec<u8>>(2).as_ref());
            u
        }).unwrap()
}

pub fn test() {
    let conn = Connection::open("test").unwrap();

    create_table(&conn, "passwords", "");
    create_table(&conn, "verify", "");

    match conn.execute("CREATE TABLE passwords (
                id          BLOB PRIMARY KEY,
                password    BLOB NOT NULL,
                nonce       BLOB NOT NULL
            )", &[]) {
        Ok(i) => println!("{} ok!", i),
        Err(i) => println!("{:?} not ok!", i),
    }
}
