mod artifact;
mod diff;
mod passes;
mod ui;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use crate::artifact::Analysis;
use crate::passes::{PassRegistry, run_report};

#[derive(Debug, Parser)]
#[command(version = option_env!("BDIFF_VERSION").unwrap_or("dev"), about)]
struct Cli {
    /// The binary or archive on the left side.
    left: PathBuf,

    /// The binary or archive on the right side.
    right: PathBuf,

    /// Print a non-interactive report instead of opening the TUI.
    #[arg(long)]
    report: bool,

    /// Maximum nested archive/container discovery depth.
    #[arg(long, default_value_t = 8)]
    max_depth: usize,

    /// Stop an individual external tool after this many seconds (0 disables).
    #[arg(long, default_value_t = 120)]
    tool_timeout_seconds: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let registry = PassRegistry::builtin();
    let analysis = Analysis::open(&cli.left, &cli.right, cli.max_depth)?;
    if cli.report {
        run_report(&analysis, &registry, cli.tool_timeout_seconds)
    } else {
        ui::run(analysis, registry, cli.tool_timeout_seconds)
    }
}
