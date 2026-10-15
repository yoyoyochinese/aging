use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};

mod crypt;
mod ui;

#[derive(Parser)]
#[command(
    name = "aging",
    about = "Encrypt to a GitHub user's SSH keys, decrypt with your own SSH key (age format)",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt to the SSH keys of a GitHub user
    Encrypt {
        /// GitHub username
        user: String,
        #[command(flatten)]
        io: InOut,
    },
    /// Decrypt with your SSH private key
    Decrypt {
        #[command(flatten)]
        io: InOut,
        /// SSH private key (default: ~/.ssh/id_ed25519)
        #[arg(short = 'k', long)]
        identity: Option<PathBuf>,
    },
}

#[derive(Args)]
struct InOut {
    /// Input text (stdin is read when neither TEXT nor --file is given)
    // Hyphen values: armored ciphertext starts with "-----BEGIN".
    #[arg(conflicts_with = "file", allow_hyphen_values = true)]
    text: Option<String>,

    /// Read input from a file
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Write output to a file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Overwrite the --output file if it exists
    #[arg(long, requires = "output")]
    force: bool,
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        ui::error(&format!("{e:#}"));
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Encrypt { user, io } => {
            let input = read_input(&io)?;
            let (recipients, skipped) = crypt::parse_keys(&crypt::fetch_keys(&user)?);
            for kind in &skipped {
                ui::warn(&format!("skipping unsupported key type: {kind}"));
            }
            if recipients.is_empty() {
                bail!("{user} has no ed25519/rsa SSH keys on GitHub");
            }
            write_output(&io, crypt::encrypt(&recipients, &input)?.as_bytes())
        }
        Commands::Decrypt { io, identity } => {
            let input = read_input(&io)?;
            let path = match identity {
                Some(p) => p,
                None => dirs::home_dir()
                    .context("cannot find home directory")?
                    .join(".ssh/id_ed25519"),
            };
            let key = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            write_output(&io, &crypt::decrypt(&input, &key, &path.display().to_string())?)
        }
    }
}

fn read_input(io: &InOut) -> Result<Vec<u8>> {
    if let Some(text) = &io.text {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(path) = &io.file {
        return fs::read(path).with_context(|| format!("cannot read {}", path.display()));
    }
    let mut stdin = io::stdin();
    if stdin.is_terminal() {
        bail!("no input: pass TEXT, --file <path>, or pipe into stdin");
    }
    let mut buf = Vec::new();
    stdin.read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_output(io: &InOut, data: &[u8]) -> Result<()> {
    let Some(path) = &io.output else {
        let mut out = io::stdout().lock();
        if !out.is_terminal() {
            return Ok(out.write_all(data)?);
        }
        let text = std::str::from_utf8(data)
            .map_err(|_| anyhow!("output is binary; write it to a file with -o <path>"))?;
        out.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            out.write_all(b"\n")?;
        }
        return Ok(());
    };

    let mut opts = OpenOptions::new();
    opts.write(true);
    if io.force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut file = opts.open(path).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => {
            anyhow!("{} already exists (use --force to overwrite)", path.display())
        }
        _ => anyhow!(e).context(format!("cannot write {}", path.display())),
    })?;
    file.write_all(data)?;
    ui::success(&format!("wrote {}", path.display()));
    Ok(())
}
