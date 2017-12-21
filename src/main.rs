extern crate clap;
extern crate rpassword;
extern crate rusqlite;
extern crate shellexpand;
extern crate sodiumoxide;

use std::{error,ffi,fs,io,path,process};

use clap::{App,Arg,SubCommand};

pub use rpassword::prompt_password_stderr as prompt_passw;

mod commands;
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
        .subcommand(SubCommand::with_name("ls"))
        .subcommand(SubCommand::with_name("gen")
            .arg(Arg::with_name("length")
                 .short("l")
                 .long("length")
                 .value_name("LENGTH")
                 .default_value("24")
                 .validator(|s| s.chars().map(|x| x.is_digit(10)).all())
                 .help("The length of the password to generate"))
            .arg(Arg::with_name("lower")
                 .short("a")
                 .long("lower")
                 .value_name("ON")
                 .default_value("y")
                 .allowed_values(&["y", "n"])
                 .help("Whether to include lower-case letters"))
            .arg(Arg::with_name("lower")
                 .short("a")
                 .long("lower")
                 .value_name("ON")
                 .default_value("y")
                 .allowed_values(&["y", "n"])
                 .help("Whether to include lower-case letters"))
            .arg(Arg::with_name("lower")
                 .short("a")
                 .long("lower")
                 .value_name("ON")
                 .default_value("y")
                 .allowed_values(&["y", "n"])
                 .help("Whether to include lower-case letters"))
            .arg(Arg::with_name("name")
                 .required(true)
                 .help("The name of the password to generate")
                 .last()))
        .subcommand(SubCommand::with_name("get")
            .arg(Arg::with_name("name")
                 .required(true)
                 .help("The name of the password to get")))
        .subcommand(SubCommand::with_name("rm")
            .arg(Arg::with_name("name")
                 .required(true)
                 .help("The name of the password to get")))
        .get_matches();

    eprintln!("{:?}", app_m);

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
    if !crypto::verify_file(&user, &key, &conn) {
        return Err("Password file invalid, possibly tampered with".into());
    }

    match app_m.subcommand() {
        (command, Some(sub_m)) => {
            let func = commands::COMMANDS.iter()
                .find(|ent| ent.0 == command)
                .unwrap().1;
            func(sub_m, &user, &key, &mut conn)
        },
        _ => panic!(),
    }
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

    eprintln!("DBPATH {:?}", dbpath);
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

    eprint!("No config found, creating new one.\n");
    eprint!("Password file location: ");
    io::stdout().flush().unwrap();
    let mut path = String::new();
    io::stdin().read_line(&mut path).unwrap();

    match fs::File::create(confpath) {
        Ok(mut file) => {
            write!(file, "DATABASE={}\n", path.trim())
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
    eprintln!("Creating new user");
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

fn do_setup(conn: &mut database::Connection) {
    let pw = prompt_passw("Master password: ").unwrap();
    let (mut user, key) = crypto::create_user(&pw);

    user.sig = crypto::compute_file_sig(&key, conn);

    eprintln!("{:?} {:?} {:?}", user, pw, key);

    database::set_user(conn, &user);
}

fn do_test(conn: &database::Connection) {
    let user = database::get_user(&conn).unwrap();
    let pw = prompt_passw("Master password: ").unwrap();
    let key = crypto::get_key(&user, &pw);
    eprintln!("{:?} {:?} {:?}", user, pw, key);
    eprintln!("verify: {:?}", crypto::verify_file(&user, &key, conn));
}
