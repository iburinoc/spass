extern crate clap;
extern crate rpassword;
extern crate rusqlite;
extern crate shellexpand;
extern crate sodiumoxide;

use std::{error,ffi,fs,io,path,process};

use clap::{App,Arg,ArgMatches,SubCommand};

use rpassword::prompt_password_stderr as prompt_passw;

mod crypto;
mod database;
mod types;

use database::Connection;
use types::User;

fn main() {
    process::exit(match run_app() {
        Ok(_) => 0,
        Err(msg) => { eprintln!("{}", msg); 1 },
    })
}

fn run_app() -> Result<(), String> {
    let app_m = App::new("spass")
        .version("2.0")
        .about("Password manager")
        .author("Sean Purcell")
        .arg(Arg::with_name("database")
             .short("d")
             .long("database")
             .value_name("FILE")
             .help("Use a specific database file"))
        .subcommand(SubCommand::with_name("add")
            .arg(Arg::with_name("name")
                 .required(true)
                 .help("The name of the password to add")))
        .get_matches();

    println!("{:?}", app_m);

    if app_m.subcommand_name() == None {
        return Err(app_m.usage().into());
    }

    crypto::init();
    let mut conn = try!(open_database(app_m.value_of_os("database")));

    let (user, key) = match database::get_user(&conn) {
        Some(user) => {
            let passw = prompt_passw("Master password: ").unwrap();
            let key = crypto::get_key(&user, &passw);
            (user, key)
        },
        None => try!(create_user(&mut conn)),
    };

    match app_m.subcommand() {
        ("add", Some(sub_m)) => add(sub_m),
        _ => panic!(),
    }

    /*
    println!("{:?}", matches);

    crypto::init();
    let mut conn = database::init("test");

    do_setup(&mut conn);

    do_test(&conn);
    */
}

fn open_database(dbarg: Option<&ffi::OsStr>) -> Result<Connection, String> {
    let path = if let Some(path) = dbarg {
        path.to_os_string()
    } else {
        try!(get_dbpath())
    };

    let dbpath = path::PathBuf::from(
        &*shellexpand::tilde(
            &*path.to_string_lossy()));

    println!("DBPATH {:?}", dbpath);
    Ok(database::init(dbpath.as_ref()))
}

static CONFPATH: &'static str = "~/.spass.conf";

fn get_dbpath() -> Result<ffi::OsString, String> {
    let expath = path::PathBuf::from(&*shellexpand::tilde(CONFPATH));
    match fs::File::open(path::Path::new(&*expath)) {
        Ok(mut file) => {
            use io::Read;

            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            let path = contents 
               .split('=')
               .nth(1)
               .unwrap()
               .trim();
            Ok(path.into())
        },
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                create_conf(&expath)
            } else {
                use error::Error;

                Err(err.description().to_string())
            }
        }
    }
}

fn create_conf(confpath: &path::Path) -> Result<ffi::OsString, String> {
    use io::Write;

    print!("No config found, creating new one.\n");
    print!("Password file location: ");
    io::stdout().flush().unwrap();
    let mut path = String::new();
    io::stdin().read_line(&mut path).unwrap();

    match fs::File::create(confpath) {
        Ok(mut file) => {
            write!(file, "DATABASE={}", path.trim())
                .unwrap();

            Ok(path.trim().into())
        },
        Err(err) => {
            use error::Error;

            Err(err.description().into())
        }
    }
}

fn create_user(conn: &mut database::Connection) ->
        Result<(User, crypto::Key), String> {
    let pw = prompt_passw("Master password: ").unwrap();
    let cpw = prompt_passw("Confirm master password: ").unwrap();

    if pw != cpw {
        return Err("Passwords don't match".into());
    }

    let (mut user, key) = crypto::create_user(&pw);

    database::reset(conn);

    user.sig = crypto::compute_file_sig(&key, conn);

    database::set_user(conn, &user);

    Ok((user, key))
}

fn add(args: &ArgMatches) -> Result<(), String> {
    println!("{:?}", args);
    Err("Error: Not implemented".into())
}

fn do_setup(conn: &mut database::Connection) {
    let pw = prompt_passw("Master password: ").unwrap();
    let (mut user, key) = crypto::create_user(&pw);

    user.sig = crypto::compute_file_sig(&key, conn);

    println!("{:?} {:?} {:?}", user, pw, key);

    database::set_user(conn, &user);
}

fn do_test(conn: &database::Connection) {
    let user = database::get_user(&conn).unwrap();
    let pw = prompt_passw("Master password: ").unwrap();
    let key = crypto::get_key(&user, &pw);
    println!("{:?} {:?} {:?}", user, pw, key);
    println!("verify: {:?}", crypto::verify_file(&user, &key, conn));
}
