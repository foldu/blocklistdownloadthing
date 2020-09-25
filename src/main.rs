use atomicwrites::{AtomicFile, OverwriteBehavior};
use clap::Clap;
use eyre::Context;
use once_cell::sync::Lazy;
use regex::Regex;
use std::{collections::BTreeSet, io::Write, path::PathBuf, time::Duration};
use url::Url;

fn main() -> Result<(), eyre::Error> {
    let opt = Opt::parse();
    let config = std::fs::read_to_string(&opt.config)
        .with_context(|| format!("Can't read {}", opt.config.display()))?;

    let config: Config = serde_json::from_str(&config)
        .with_context(|| format!("Can't parse {}", opt.config.display()))?;

    let whitelist = config
        .host_whitelist
        .iter()
        .map(|url| url.as_str().to_string())
        .collect::<BTreeSet<_>>();

    let mut merged = BTreeSet::new();

    for host in &config.host_blacklist {
        merged.insert(host.as_str().to_owned());
    }

    for blocklist_url in config.blocklists {
        let req = ureq::get(blocklist_url.as_str())
            .timeout(Duration::from_secs(5))
            .call();
        if !req.ok() {
            eprintln!("Failed fetching blocklist {}", blocklist_url);
            continue;
        }
        match req.into_string() {
            Err(e) => {
                eprintln!("Could not fetch blocklist {}: {}", blocklist_url, e);
            }
            Ok(blocklist) => match parse_blocklist(&blocklist) {
                Ok(blocklist) => {
                    for host in blocklist {
                        if !whitelist.contains(&host) {
                            merged.insert(host);
                        }
                    }
                }
                Err(e) => eprintln!("In blocklist {}: {}", blocklist_url, e),
            },
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    if let Some(ref path) = opt.out {
        AtomicFile::new(&path, OverwriteBehavior::AllowOverwrite)
            .write(|mut w| -> Result<(), std::io::Error> {
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

    Ok(())
}

#[derive(Clone, Copy)]
enum BlocklistOutput {
    Unbound,
}

impl BlocklistOutput {
    fn write_to<W: Write>(self, merged: &BTreeSet<String>, mut w: W) -> Result<(), std::io::Error> {
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
    host_whitelist: Vec<String>,
    host_blacklist: Vec<String>,
    blocklists: Vec<Url>,
}
