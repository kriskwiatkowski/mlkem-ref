use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

const KATWALK_VERSION: &str = "0.0.15";
const VECTOR_REPOSITORY: &str = "https://github.com/kriskwiatkowski/crypto-test-vectors.git";
const VECTOR_REVISION: &str = "5435bd2d90b97d26d4a7bb91e106ce8bbc45af5d";
const OUT_DIR: &str = "target/kat_out";

fn main() {
    match env::args().nth(1).as_deref() {
        Some("kat") => run_kats(),
        _ => Err("usage: cargo xtask kat".into()),
    }
    .unwrap_or_else(|error| {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    });
}

fn run_kats() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    let target = root.join("target");
    let vectors = target.join("crypto-test-vectors");
    let tools = target.join("kat-tools");

    checkout_vectors(&vectors)?;
    install_katwalk(&tools)?;

    run(Command::new("cargo").current_dir(&root).args([
        "build",
        "--release",
        "--bin",
        "mlkem_wrapper",
    ]))?;

    let wrapper = target.join("release/mlkem_wrapper");
    let katwalk = tools.join("bin/katwalk");
    let fips_vectors = vectors.join("vectors/acvp/FIPS-203");
    run_kat(
        &katwalk,
        &wrapper,
        &fips_vectors.join("keyGen"),
        &target.join("keygen_out.json"),
    )?;
    run_kat(
        &katwalk,
        &wrapper,
        &fips_vectors.join("encapsDecap"),
        &target.join("encapsDecap_out.json"),
    )
}

fn checkout_vectors(vectors: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !vectors.exists() {
        run(Command::new("git")
            .args(["clone", "--no-checkout", VECTOR_REPOSITORY])
            .arg(vectors))?;
    }

    run(Command::new("git").args(["-C"]).arg(vectors).args([
        "fetch",
        "--depth",
        "1",
        "origin",
        VECTOR_REVISION,
    ]))?;
    run(Command::new("git").args(["-C"]).arg(vectors).args([
        "checkout",
        "--detach",
        VECTOR_REVISION,
    ]))
}

fn install_katwalk(tools: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let binary = tools.join("bin/katwalk");
    let version_file = tools.join("katwalk-version");
    let installed_version = fs::read_to_string(&version_file).unwrap_or_default();

    if binary.is_file() && installed_version.trim() == KATWALK_VERSION {
        return Ok(());
    }

    run(Command::new("cargo").args([
        "install",
        "--locked",
        "--force",
        "--root",
        tools.to_str().ok_or("tools path is not valid UTF-8")?,
        "katwalk",
        "--version",
        KATWALK_VERSION,
    ]))?;
    fs::write(version_file, format!("{KATWALK_VERSION}\n"))?;
    Ok(())
}

fn run_kat(
    katwalk: &Path,
    wrapper: &Path,
    test_directory: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    run(Command::new(katwalk).args([
        "--wrapper",
        wrapper.to_str().ok_or("wrapper path is not valid UTF-8")?,
        "--in",
        test_directory
            .join("prompt.json")
            .to_str()
            .ok_or("input path is not valid UTF-8")?,
        "--out",
        output.to_str().ok_or("output path is not valid UTF-8")?,
        "--expected",
        test_directory
            .join("expectedResults.json")
            .to_str()
            .ok_or("expected-results path is not valid UTF-8")?,
    ]))
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask has no workspace parent".into())
}

fn run(command: &mut Command) -> Result<(), Box<dyn std::error::Error>> {
    let status = command.status()?;
    successful(status, command)
}

fn successful(status: ExitStatus, command: &Command) -> Result<(), Box<dyn std::error::Error>> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed ({status}): {command:?}").into())
    }
}
