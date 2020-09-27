use atomicwrites::{AtomicFile, OverwriteBehavior};
use clap::Clap;
use eyre::Context;
use once_cell::sync::Lazy;
use regex::Regex;
use std::{
    collections::BTreeSet,
    convert::TryFrom,
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
                for host in parse_blocklist(&hosts) {
                    match host {
                        Ok(host) => {
                            if !host_whitelist.contains(&host) {
                                merged.insert(host);
                            }
                        }
                        Err(e) => {
                            eprintln!("In blocklist {}: {}", blocklist_url, e);
                            failed = true;
                        }
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

fn fetch_blocklist(blocklist_url: &Url) -> Result<String, eyre::Error> {
    let req = ureq::get(blocklist_url.as_str())
        .timeout(Duration::from_secs(5))
        .call();
    if !req.ok() {
        eyre::bail!("{} returned status {}", blocklist_url, req.status());
    }

    req.into_string()
        .with_context(|| format!("Could not fetch blocklist {}", blocklist_url))
}

#[derive(Clone, Copy)]
enum BlocklistOutput {
    Unbound,
}

impl BlocklistOutput {
    fn write_to(self, merged: &BTreeSet<Host>, mut w: impl Write) -> Result<(), std::io::Error> {
        match self {
            BlocklistOutput::Unbound => {
                for host in merged {
                    writeln!(w, "local-zone: \"{}\" always_nxdomain", host.0)?;
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

fn parse_blocklist<'a>(blocklist: &'a str) -> impl Iterator<Item = Result<Host, eyre::Error>> + 'a {
    static HOST_REGEX: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"^\s*((?P<ip>\S+)\s+)?(?P<host>\S+)\s*$"#).unwrap());
    static COMMENT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new("#.*").unwrap());

    blocklist
        .lines()
        .map(|line| COMMENT_REGEX.replace(line, ""))
        .filter(|line| !line.is_empty() && !line.chars().all(|c| c.is_whitespace()))
        .filter_map(|line| match HOST_REGEX.captures(&line) {
            Some(captures) => {
                if captures.name("ip").map(|ip| ip.as_str()) != Some("127.0.0.1") {
                    let host = captures.name("host").unwrap().as_str().to_owned();
                    Some(Host::try_from(host))
                } else {
                    None
                }
            }
            None => Some(Err(eyre::format_err!(
                "Failed parsing blocklist entry \"{}\"",
                line
            ))),
        })
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
struct Host(String);

impl TryFrom<String> for Host {
    type Error = eyre::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // FIXME: figuring out valid domain names is hard and I don't want to
        // read all related RFC's so just check if the string is empty or has
        // whitespace
        if value.is_empty() || value.chars().any(|c| c.is_whitespace()) {
            Err(eyre::format_err!("{} is not a valid domain name", value))
        } else {
            Ok(Self(value))
        }
    }
}

impl<'de> serde::Deserialize<'de> for Host {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(|e| serde::de::Error::custom(e))
    }
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
    host_whitelist: BTreeSet<Host>,
    host_blacklist: BTreeSet<Host>,
    blocklists: Vec<Url>,
}
