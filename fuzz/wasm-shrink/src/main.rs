use std::io::Write;

use anyhow::Context;

/// Test case reducer powered by wasm-smith
#[derive(clap::Parser)]
struct Arguments {
    /// Path to standalone target executable
    #[arg(long)]
    target: std::path::PathBuf,
    /// Path to crashing test input
    #[arg(short, long)]
    input: std::path::PathBuf,
    /// Path where the final shrunken WASM module is written
    #[arg(short, long)]
    output: std::path::PathBuf,
    /// RNG seed used to decide which mutations are used
    #[arg(long, default_value_t = 15)] // Initial seed provided by my mom & dad
    seed: u64,
    /// Maximum number of attempts to shirnk
    #[arg(long, default_value_t = 1000)]
    attempts: u32,
    /// String to search for in output of target executable
    #[arg(long)]
    predicate: Option<String>,
}

fn main() -> anyhow::Result<()> {
    log::set_logger(&Logger).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let args = <Arguments as clap::Parser>::parse();
    let output_path = args.output.as_path();

    let initial_module = run_on_initial_input(&args)?;

    let mut output = std::fs::File::create(output_path)
        .with_context(|| format!("could not open output file {:?}", output_path))?;

    let args_ref = &args;
    let shrink = wasm_shrink::WasmShrink::default()
        .attempts(args.attempts)
        .seed(args.seed)
        .run(initial_module, &mut |wasm: &[u8]| run(args_ref, wasm))?;

    eprintln!(
        "shrunk {} bytes to {}",
        shrink.input_size, shrink.output_size
    );
    output.write_all(shrink.output.as_slice())?;

    return Ok(());
}

fn run_on_initial_input(args: &Arguments) -> anyhow::Result<Vec<u8>> {
    let target_path = args.target.as_path();
    let initial_output = std::process::Command::new(target_path)
        .args([
            "--input".as_ref(),
            args.input.as_path(),
            "--save-module".as_ref(),
            "-".as_ref(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .with_context(|| format!("could not spawn {:?}", target_path))?;

    if initial_output.status.success() {
        anyhow::bail!("initial run unexpectedly succeeded");
    }

    if initial_output.stdout.is_empty() {
        anyhow::bail!("initial run did not produce a WASM module");
    }

    // No need to check predicate here, since `wasm-smith` will do it for us

    return Ok(initial_output.stdout);
}

fn run(args: &Arguments, wasm: &[u8]) -> anyhow::Result<bool> {
    let target_path = args.target.as_path();
    let mut spawned = std::process::Command::new(target_path)
        .args([
            "--input".as_ref(),
            args.input.as_path(),
            "--replace-module".as_ref(),
            "-".as_ref(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("could not spawn {:?}", target_path))?;

    std::io::Write::write_all(&mut spawned.stdin.take().unwrap(), wasm)?;

    let output = spawned
        .wait_with_output()
        .context("error waiting on process output")?;

    if output.status.success() {
        Ok(false)
    } else if let Some(predicate) = &args.predicate {
        str::from_utf8(&output.stderr)
            .context("cannot search for predicate, stderr was not valid UTF-8")
            .map(|captured_stderr| captured_stderr.contains(predicate))
    } else {
        Ok(true)
    }
}

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!("{}: {}", record.level(), record.args());
    }

    fn flush(&self) {}
}
