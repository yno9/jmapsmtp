//! SMTP <-> JMAP bridge.
//!
//! Port of `github.com/yno9/go-jmapsmtp` @ `1b5cf06`. See PLAN.md.

fn main() {
    // M4 replaces this with the real startup sequence (main.go's main()):
    // read config -> load PGP entity -> load dynamic domains -> cleanup
    // orphaned data -> load/generate DKIM keys -> build stores and aliases ->
    // recover dynamic accounts -> start maintenance -> start SMTP -> serve JMAP.
    println!("jmapsmtp {} (port in progress)", env!("CARGO_PKG_VERSION"));
}
