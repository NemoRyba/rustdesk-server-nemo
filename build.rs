fn main() {
    hbb_common::gen_version();
    nemo_build_id();
}

// Bake a build id (git short hash + commit date, "+" when the tree has uncommitted
// SOURCE changes) into hbbs so the admin dashboard can show WHICH build is running.
// db_v2.sqlite3 is the live DB and is always "modified", so it is excluded from the
// dirty check. Best-effort: outside a git checkout it falls back to "unknown".
fn nemo_build_id() {
    fn git(args: &[&str]) -> Option<String> {
        let out = std::process::Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
    let hash = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    let date = git(&["show", "-s", "--format=%cs", "HEAD"]).unwrap_or_default();
    // Any tracked change other than the live DB makes this a dirty (uncommitted)
    // build. Let git evaluate the pathspec exclusion so line-ending/normalization
    // is handled correctly (a substring compare misfired on scp'd working copies).
    let dirty = git(&[
        "status",
        "--porcelain",
        "--untracked-files=no",
        "--",
        ".",
        ":!db_v2.sqlite3",
    ])
    .map(|s| !s.trim().is_empty())
    .unwrap_or(false);
    println!(
        "cargo:rustc-env=NEMO_BUILD_ID={}{}{}{}",
        hash,
        if dirty { "+" } else { "" },
        if date.is_empty() { "" } else { " " },
        date
    );
    // Refresh on commits/branch switches. (A dirty edit alone doesn't retrigger
    // build.rs — the hash part stays correct; the "+" marker is best-effort.)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}
