extern crate rusqlite;

use rusqlite::{Connection, Result};

fn create_table(conn: &Connection, name: &str, schema: &str) {
    let exists: Result<i32> = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name = $1",
        &[&name],
        |row| { row.get(0) } );
    println!("{:?}", exists);
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
