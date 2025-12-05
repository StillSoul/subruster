use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use futures::{stream, StreamExt};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH}; // Duration is now used
use tokio::sync::Mutex;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Parser, Debug)]
#[clap(name = "subruster", version = "2.0.0", author = "YourName")]
struct Args {
    #[clap(short, long)]
    domain: String,

    #[clap(short, long, value_name = "FILE")]
    wordlist: PathBuf,

    #[clap(short, long, default_value_t = 100)]
    concurrency: usize,

    #[clap(long, default_value_t = 5)]
    timeout: u64,

    #[clap(short, long)]
    output: Option<PathBuf>,

    #[clap(short, long)]
    silent: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !args.silent {
        print_banner();
        println!(
            "[*] Target: {}\n[*] Threads: {}\n[*] Wordlist: {:?}",
            args.domain.cyan(),
            args.concurrency.to_string().yellow(),
            args.wordlist
        );
    }

    // FIX 1: Removed .context() check.
    // The constructor returns the instance directly, not a Result.
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Detect wildcard (returns Option<IP_String>)
    let wildcard_ip = detect_wildcard(&resolver, &args.domain).await;

    if !args.silent {
        if let Some(ref ip) = wildcard_ip {
            println!(
                "{} Wildcard detected! Filtering results pointing to: {}",
                "[!]".yellow(),
                ip.to_string().red()
            );
        }
    }

    let subdomains = load_wordlist(&args.wordlist).context("Failed to read wordlist")?;
    if !args.silent {
        println!(
            "[*] Loaded {} words. Starting enumeration...",
            subdomains.len()
        );
    }

    let found_domains = Arc::new(Mutex::new(Vec::new()));

    // Pre-calculate timeout duration to avoid doing it inside the loop
    let timeout_duration = Duration::from_secs(args.timeout);

    let lookup_stream = stream::iter(subdomains);

    lookup_stream
        .for_each_concurrent(args.concurrency, |sub| {
            // Clone references for the async block
            let resolver = &resolver;
            let domain = &args.domain;
            let found_domains = found_domains.clone();
            let wildcard_ip = wildcard_ip.clone();
            let silent = args.silent;

            async move {
                let full_domain = format!("{}.{}", sub, domain);

                // FIX 2: Added actual Timeout logic using tokio::time::timeout
                // This ensures the generic DNS lookup doesn't hang forever.
                let lookup_future = resolver.lookup_ip(&full_domain);

                match tokio::time::timeout(timeout_duration, lookup_future).await {
                    // Timeout did not occur, and DNS resolution succeeded
                    Ok(Ok(lookup)) => {
                        if let Some(ip) = lookup.iter().next() {
                            let ip_str = ip.to_string();

                            // Filter out wildcard IPs
                            let is_noise =
                                wildcard_ip.as_ref().map_or(false, |w_ip| *w_ip == ip_str);

                            if !is_noise {
                                if !silent {
                                    println!(
                                        "{} {}  => {}",
                                        "[+]".green(),
                                        full_domain.bold(),
                                        ip_str.dimmed()
                                    );
                                } else {
                                    println!("{}", full_domain);
                                }

                                let mut lock = found_domains.lock().await;
                                lock.push(full_domain);
                            }
                        }
                    }
                    // Ignore Timeouts (Ok(Err)) or DNS Errors (Err)
                    _ => {}
                }
            }
        })
        .await;

    if let Some(path) = args.output {
        let results = found_domains.lock().await;
        let mut file = File::create(&path).context("Could not create output file")?;
        for line in results.iter() {
            writeln!(file, "{}", line)?;
        }
        if !args.silent {
            println!("\n[✓] Saved {} results to {:?}", results.len(), path);
        }
    }

    Ok(())
}

fn load_wordlist(path: &PathBuf) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let words = reader
        .lines()
        .filter_map(|line| line.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    Ok(words)
}

async fn detect_wildcard(resolver: &TokioAsyncResolver, domain: &str) -> Option<String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let noise_domain = format!("wildcard-check-{}.{}", nonce, domain);

    // We also apply a short timeout to the wildcard check
    let lookup =
        tokio::time::timeout(Duration::from_secs(3), resolver.lookup_ip(noise_domain)).await;

    match lookup {
        Ok(Ok(ips)) => ips.iter().next().map(|ip| ip.to_string()),
        _ => None,
    }
}

fn print_banner() {
    println!(
        "{}",
        r#"
   _____       __    ____             __           
  / ___/__  __/ /_  / __ \__  _______/ /____  _____
  \__ \/ / / / __ \/ /_/ / / / / ___/ __/ _ \/ ___/
 ___/ / /_/ / /_/ / _, _/ /_/ (__  ) /_/  __/ /    
/____/\__,_/_.___/_/ |_|\__,_/____/\__/\___/_/     
        Custom Rust Enumerator v2.0
    "#
        .bold()
        .blue()
    );
}
