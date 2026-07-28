//! Entry point. Everything of substance lives in the library.

fn main() {
    // M6 replaces this with the real startup sequence (main.go's main()):
    // read config -> load PGP entity -> load dynamic domains -> cleanup
    // orphaned data -> load/generate DKIM keys -> build stores and aliases ->
    // recover dynamic accounts -> start maintenance -> start SMTP -> serve
    // JMAP.
    println!("jmapsmtp {} (port in progress)", env!("CARGO_PKG_VERSION"));
}
