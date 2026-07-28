//! Comparing two captured runs and reporting the differences.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;

use super::normalize;

/// One request/response, already normalised.
pub struct Capture {
    pub name: String,
    pub request: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Everything one instance produced.
pub struct Side {
    pub label: String,
    pub steps: Vec<Capture>,
    /// Relative path -> normalised contents.
    pub data: BTreeMap<String, String>,
    pub log: String,
}

impl Side {
    /// Dump everything captured, in a form meant to be read and diffed by
    /// hand. Written unconditionally: when a run fails, this is what tells
    /// you what the two sides actually said, and reconstructing it after the
    /// fact means running everything again.
    pub fn write_transcript(&self, path: &Path) -> Result<()> {
        use std::fmt::Write as _;
        let mut out = String::new();
        writeln!(out, "# side: {}\n", self.label)?;
        for c in &self.steps {
            writeln!(out, "── {} — {} → {}", c.name, c.request, c.status)?;
            for (k, v) in &c.headers {
                writeln!(out, "   {k}: {v}")?;
            }
            if !c.body.is_empty() {
                writeln!(out, "   ┄")?;
                for line in c.body.lines() {
                    writeln!(out, "   {line}")?;
                }
            }
            writeln!(out)?;
        }
        writeln!(out, "\n# data/\n")?;
        for (p, content) in &self.data {
            writeln!(out, "── {p}")?;
            for line in content.lines() {
                writeln!(out, "   {line}")?;
            }
            writeln!(out)?;
        }
        writeln!(out, "\n# log\n{}", self.log)?;
        std::fs::write(path, out)?;
        Ok(())
    }
}

pub enum Diff {
    Status {
        step: String,
        request: String,
        left: u16,
        right: u16,
    },
    Headers {
        step: String,
        left: Vec<(String, String)>,
        right: Vec<(String, String)>,
    },
    Body {
        step: String,
        request: String,
        left: String,
        right: String,
    },
    DataMissing {
        path: String,
        present_in: String,
    },
    DataContent {
        path: String,
        left: String,
        right: String,
    },
    Log {
        left: String,
        right: String,
    },
}

pub struct Report {
    diffs: Vec<Diff>,
    left_label: String,
    right_label: String,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.diffs.is_empty()
    }
    pub fn count(&self) -> usize {
        self.diffs.len()
    }

    pub fn print(&self) {
        if self.diffs.is_empty() {
            return;
        }
        let (l, r) = (&self.left_label, &self.right_label);
        for d in &self.diffs {
            println!();
            match d {
                Diff::Status {
                    step,
                    request,
                    left,
                    right,
                } => {
                    println!("── status: {step} ({request})");
                    println!("   {l}: {left}");
                    println!("   {r}: {right}");
                }
                Diff::Headers { step, left, right } => {
                    println!("── headers: {step}");
                    println!("   {l}: {left:?}");
                    println!("   {r}: {right:?}");
                }
                Diff::Body {
                    step,
                    request,
                    left,
                    right,
                } => {
                    println!("── body: {step} ({request})");
                    print_line_diff(l, left, r, right);
                }
                Diff::DataMissing { path, present_in } => {
                    println!("── data/: {path} exists only in {present_in}");
                }
                Diff::DataContent { path, left, right } => {
                    println!("── data/: {path}");
                    print_line_diff(l, left, r, right);
                }
                Diff::Log { left, right } => {
                    println!("── server log");
                    print_line_diff(l, left, r, right);
                }
            }
        }
    }
}

pub fn compare(left: &Side, right: &Side) -> Report {
    let mut diffs = Vec::new();

    // Step counts always match: both sides replay the same scenario, and a
    // transport error aborts the run before it gets here.
    for (a, b) in left.steps.iter().zip(right.steps.iter()) {
        debug_assert_eq!(a.name, b.name);
        if a.status != b.status {
            diffs.push(Diff::Status {
                step: a.name.clone(),
                request: a.request.clone(),
                left: a.status,
                right: b.status,
            });
        }
        if a.headers != b.headers {
            diffs.push(Diff::Headers {
                step: a.name.clone(),
                left: a.headers.clone(),
                right: b.headers.clone(),
            });
        }
        if a.body != b.body {
            diffs.push(Diff::Body {
                step: a.name.clone(),
                request: a.request.clone(),
                left: a.body.clone(),
                right: b.body.clone(),
            });
        }
    }

    for (path, content) in &left.data {
        match right.data.get(path) {
            None => diffs.push(Diff::DataMissing {
                path: path.clone(),
                present_in: left.label.clone(),
            }),
            Some(other) if other != content => diffs.push(Diff::DataContent {
                path: path.clone(),
                left: content.clone(),
                right: other.clone(),
            }),
            Some(_) => {}
        }
    }
    for path in right.data.keys() {
        if !left.data.contains_key(path) {
            diffs.push(Diff::DataMissing {
                path: path.clone(),
                present_in: right.label.clone(),
            });
        }
    }

    // The log is part of the compatibility contract too: PLAN.md §5.1 keeps
    // the "[smtp]" / "[setup]" / "[provision]" prefixes because operators
    // grep for them. It also catches a whole class of silent divergence —
    // work one side did at startup and the other skipped.
    if left.log != right.log {
        diffs.push(Diff::Log {
            left: left.log.clone(),
            right: right.log.clone(),
        });
    }

    Report {
        diffs,
        left_label: left.label.clone(),
        right_label: right.label.clone(),
    }
}

/// Walk `data/` and record every file, normalised.
///
/// Binary files are recorded by length rather than content: a PGP key or a
/// DER blob has no useful line diff, and the ones that matter are seeded
/// identically anyway (`fixture.rs`), so a length change is enough of a
/// tripwire.
pub fn snapshot_data(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            let path = e.path();
            if e.file_type()?.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let bytes = std::fs::read(&path)?;
            let value = match String::from_utf8(bytes) {
                Ok(text) => {
                    // delta.json's change-record arrays are built by ranging
                    // over a Go map, so their order is whatever that run's
                    // hash seed produced — two Go runs disagree with each
                    // other. Sorting compares what the records are (sets of
                    // ids) and leaves every other byte strictly compared.
                    let text = if rel.ends_with("delta.json") {
                        sort_json_arrays(&text)
                    } else {
                        text
                    };
                    normalize::normalize(&text)
                }
                Err(e) => format!("<binary, {} bytes>", e.as_bytes().len()),
            };
            out.insert(rel, value);
        }
    }
    Ok(out)
}

/// Sort every array in a JSON document, recursively. Returns the input
/// unchanged when it does not parse.
fn sort_json_arrays(json: &str) -> String {
    fn walk(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Array(items) => {
                for i in items.iter_mut() {
                    walk(i);
                }
                items.sort_by_key(std::string::ToString::to_string);
            }
            serde_json::Value::Object(map) => {
                for (_, i) in map.iter_mut() {
                    walk(i);
                }
            }
            _ => {}
        }
    }
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(mut v) => {
            walk(&mut v);
            serde_json::to_string(&v).unwrap_or_else(|_| json.to_string())
        }
        Err(_) => json.to_string(),
    }
}

/// A minimal line-by-line diff. Not an LCS — for these payloads a positional
/// comparison points at the right line, and pulling in a diff crate to do
/// better is not worth it yet.
fn print_line_diff(left_label: &str, left: &str, right_label: &str, right: &str) {
    let la: Vec<&str> = left.lines().collect();
    let ra: Vec<&str> = right.lines().collect();
    let mut shown = 0;
    for i in 0..la.len().max(ra.len()) {
        let a = la.get(i).copied().unwrap_or("<absent>");
        let b = ra.get(i).copied().unwrap_or("<absent>");
        if a == b {
            continue;
        }
        if shown == 12 {
            println!("   … further differences suppressed");
            break;
        }
        println!("   line {}:", i + 1);
        println!("     {left_label}: {a}");
        println!("     {right_label}: {b}");
        shown += 1;
    }
}
