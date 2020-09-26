use atomicwrites::{AtomicFile, OverwriteBehavior};
use clap::Clap;
use eyre::Context;
use once_cell::sync::Lazy;
use regex::Regex;
use std::{
    collections::BTreeSet,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Duration,
};
use url::Url;

fn main() -> Result<(), eyre::Error> {
    let opt = Opt::parse();
    let config = std::fs::read_to_string(&opt.config)
        .with_context(|| format!("Can't read {}", opt.config.display()))?;

    let Config {
        host_whitelist,
        host_blacklist,
        blocklists,
    } = serde_json::from_str(&config)
        .with_context(|| format!("Can't parse {}", opt.config.display()))?;

    let mut merged = host_blacklist;

    let mut failed = false;
    for blocklist_url in blocklists {
        match fetch_blocklist(&blocklist_url) {
            Ok(hosts) => {
                for host in hosts {
                    if !host_whitelist.contains(&host) {
                        merged.insert(host);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                failed = true;
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    if let Some(ref path) = opt.out {
        AtomicFile::new(&path, OverwriteBehavior::AllowOverwrite)
            .write(|w| -> Result<(), std::io::Error> {
                let mut w = BufWriter::new(w);
                opt.format.write_to(&merged, &mut w)?;
                w.flush()?;
                Ok(())
            })
            .with_context(|| format!("Could not write to {}", path.display()))?;
    } else {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        opt.format
            .write_to(&merged, &mut stdout)
            .context("Could not write to stdout")?;
    };

    if failed {
        Err(eyre::format_err!("Some blocklists failed"))
    } else {
        Ok(())
    }
}

fn fetch_blocklist(blocklist_url: &Url) -> Result<Vec<String>, eyre::Error> {
    let req = ureq::get(blocklist_url.as_str())
        .timeout(Duration::from_secs(5))
        .call();
    if !req.ok() {
        eyre::bail!("{} returned status {}", blocklist_url, req.status());
    }

    let blocklist = req
        .into_string()
        .with_context(|| format!("Could not fetch blocklist {}", blocklist_url))?;

    parse_blocklist(&blocklist).with_context(|| format!("In blocklist {}", blocklist_url))
}

#[derive(Clone, Copy)]
enum BlocklistOutput {
    Unbound,
}

impl BlocklistOutput {
    fn write_to(self, merged: &BTreeSet<String>, mut w: impl Write) -> Result<(), std::io::Error> {
        match self {
            BlocklistOutput::Unbound => {
                for host in merged {
                    writeln!(w, "local-zone: \"{}\" always_nxdomain", host)?;
                }
            }
        }

        Ok(())
    }
}

impl std::str::FromStr for BlocklistOutput {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unbound" => Ok(BlocklistOutput::Unbound),
            _ => Err(eyre::format_err!(
                "Unknown format: {}, valid formats are: unbound",
                s
            )),
        }
    }
}

fn parse_blocklist(blocklist: &str) -> Result<Vec<String>, eyre::Error> {
    static HOST_REGEX: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"^\s*((?P<ip>\S+)\s+)?(?P<host>\S+)\s*$"#).unwrap());
    static COMMENT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new("#.*").unwrap());
    let mut ret = Vec::new();
    for line in blocklist.lines() {
        let line = COMMENT_REGEX.replace(line, "");
        if !line.is_empty() && !line.chars().all(|c| c.is_whitespace()) {
            match HOST_REGEX.captures(&line) {
                Some(captures) => {
                    if captures.name("ip").map(|ip| ip.as_str()) != Some("127.0.0.1") {
                        ret.push(captures.name("host").unwrap().as_str().to_owned());
                    }
                }
                None => {
                    eyre::bail!("Failed parsing blocklist entry \"{}\"", line);
                }
            }
        }
    }

    Ok(ret)
}

#[derive(Clap)]
struct Opt {
    /// Path to config
    #[clap(short, long)]
    config: PathBuf,

    /// Output file
    #[clap(short, long)]
    out: Option<PathBuf>,

    /// Format of the merged blocklist
    #[clap(short, long, default_value = "unbound")]
    format: BlocklistOutput,
}

#[derive(serde::Deserialize)]
struct Config {
    host_whitelist: BTreeSet<String>,
    host_blacklist: BTreeSet<String>,
    blocklists: Vec<Url>,
}
