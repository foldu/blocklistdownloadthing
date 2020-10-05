use atomicwrites::{AtomicFile, OverwriteBehavior};
use clap::Clap;
use eyre::Context;
use log::{info, warn};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    convert::TryFrom,
    io::{BufWriter, Write},
    net::IpAddr,
    path::PathBuf,
    time::Duration,
};
use url::Url;

fn main() -> Result<(), eyre::Error> {
    env_logger::from_env(env_logger::Env::default().default_filter_or("info")).init();

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

    let mut cache = Cache::new(opt.cache.clone());

    let mut failed = false;
    for blocklist_url in blocklists {
        let hosts = match fetch_blocklist(&blocklist_url) {
            Ok(hosts) => {
                if let Err(e) = cache.insert(&blocklist_url, &hosts) {
                    warn!("Failed writing to cache: {:#}", e);
                }
                hosts
            }
            Err(e) => {
                warn!("{:#}", e);
                failed = true;
                if let Ok(Some(hosts)) = cache.get(&blocklist_url) {
                    info!("Using cached version");
                    hosts
                } else {
                    continue;
                }
            }
        };

        for host in parse_blocklist(&hosts) {
            match host {
                Ok(host) => {
                    if !host_whitelist.contains(&host) {
                        merged.insert(host);
                    }
                }
                Err(e) => {
                    warn!("In blocklist {}: {}", blocklist_url, e);
                    failed = true;
                }
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

struct Cache {
    path: PathBuf,
}

impl Cache {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn insert(&mut self, url: &Url, content: &str) -> Result<(), eyre::Error> {
        std::fs::create_dir_all(&self.path)
            .with_context(|| format!("Could not create cache dir in {}", self.path.display()))?;
        let path = self.cache_path(url);
        AtomicFile::new(&path, OverwriteBehavior::AllowOverwrite)
            .write(|w| w.write_all(content.as_bytes()))
            .with_context(|| format!("Failed writing to cache file in {}", path.display()))?;
        Ok(())
    }

    pub(crate) fn get(&mut self, url: &Url) -> Result<Option<String>, eyre::Error> {
        let path = self.cache_path(url);
        match std::fs::read_to_string(&path) {
            Ok(cont) => Ok(Some(cont)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context(format!("Failed reading cached file in {}", path.display())),
        }
    }

    fn cache_path(&self, url: &Url) -> PathBuf {
        self.path.join(url.as_str().replace('/', "_"))
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
    Dnsmasq,
    Hosts,
}

impl BlocklistOutput {
    // FIXME: bad abstraction
    fn write_to(self, merged: &BTreeSet<Host>, mut w: impl Write) -> Result<(), std::io::Error> {
        match self {
            BlocklistOutput::Unbound => {
                for host in merged {
                    writeln!(w, "local-zone: \"{}\" always_nxdomain", host.0)?;
                }
            }
            BlocklistOutput::Dnsmasq => {
                for host in merged {
                    writeln!(w, "address=/{}/", host.0)?;
                }
            }
            BlocklistOutput::Hosts => {
                for host in merged {
                    writeln!(w, "0.0.0.0 {}", host.0)?;
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
            "dnsmasq" => Ok(BlocklistOutput::Dnsmasq),
            "hosts" => Ok(BlocklistOutput::Hosts),
            _ => Err(eyre::format_err!(
                "Unknown format: {}, valid formats are: unbound, dnsmasq, hosts",
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
                let ip = captures.name("ip").map(|ip| ip.as_str().parse::<IpAddr>());
                let skip = match ip {
                    Some(Ok(ip)) if ip.is_unspecified() => false,
                    None => false,
                    Some(Ok(ip)) if ip.is_loopback() => true,
                    Some(Err(e)) => return Some(Err(eyre::format_err!("Malformed ip: {}", e))),
                    Some(Ok(ip)) => return Some(Err(eyre::format_err!("Suspicious ip {}", ip))),
                };

                if skip {
                    None
                } else {
                    let host = captures.name("host").unwrap().as_str();
                    Some(Host::try_from(host.to_owned()))
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
        // read all related RFC's so just check if the string is empty,
        // has whitespace or any character that'll cause problems with
        // formatting to a blocklist entry
        if value.is_empty()
            || value
                .chars()
                .any(|c| c.is_whitespace() || c == '/' || c == '"')
        {
            Err(eyre::format_err!("{} is not a valid domain name", value))
        } else {
            Ok(Self(value))
        }
    }
}

impl<'de> Deserialize<'de> for Host {
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

    /// Output file. If not given will print blocklist to stdout
    #[clap(short, long)]
    out: Option<PathBuf>,

    /// Format of the merged blocklist
    #[clap(short, long)]
    format: BlocklistOutput,

    /// Path to cached blocklists
    #[clap(long)]
    cache: PathBuf,
}

#[derive(Deserialize)]
struct Config {
    host_whitelist: BTreeSet<Host>,
    host_blacklist: BTreeSet<Host>,
    blocklists: BTreeSet<Url>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_try_from() {
        Host::try_from("fish.com".to_owned()).unwrap();
        assert!(Host::try_from("  fish".to_owned()).is_err());
        assert!(Host::try_from("fish ".to_owned()).is_err());
        assert!(Host::try_from("fi sh".to_owned()).is_err());
        assert!(Host::try_from("".to_owned()).is_err());
    }
}
