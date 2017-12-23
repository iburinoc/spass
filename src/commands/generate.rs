extern crate sodiumoxide;

use crypto;

pub struct PasswCharset {
    pub lower: bool,
    pub upper: bool,
    pub digit: bool,
    pub sym: bool
}

fn get_chars(opts: &PasswCharset) -> Result<Vec<char>, String> {
    let mut chars = Vec::new();
    if opts.lower {
        chars.extend("abcdefghijklmnopqrstuvwxyz".chars());
    };
    if opts.upper {
        chars.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
    };
    if opts.digit {
        chars.extend("0123456789".chars());
    };
    if opts.sym {
        chars.extend("!@#$%?".chars());
    };
    if chars.len() == 0 {
        Err("No characters enabled for password generation".into())
    } else {
        Ok(chars)
    }
}

fn get_entropy(len: usize, numchars: usize) -> i64 {
    let perchar = (numchars as f64).log2();
    let total = (len as f64) * perchar;
    total as i64
}

pub fn generate(len: usize, opts: &PasswCharset) ->
        Result<(String, i64), String> {
    let chars = get_chars(opts)?;

    let mut pw = String::new();
    pw.reserve(len);

    for _ in 0..len {
        let idx = crypto::random(chars.len() as u64);
        pw.push(chars[idx as usize]);
    }

    Ok((pw, get_entropy(len, chars.len())))
}
