# SubRuster 🦀

A fast and lightweight **subdomain enumeration tool** written in Rust.  
Designed for security researchers, penetration testers, and bug bounty hunters.  

## Features
- 🔍 Subdomain enumeration via DNS lookups  
- 📂 Supports custom wordlists (or built-in defaults)  
- ⚡ Configurable concurrency (async + Tokio)  
- ⏱ Adjustable DNS timeout  
- 🎭 Wildcard subdomain detection & filtering  
- 📝 Save results to file  
- 🤫 Silent mode for clean output  

## Installation
```bash
# Clone the repo
git clone https://github.com/yourname/subruster.git
cd subruster

# Build with Cargo
cargo build --release
````

The binary will be available at:

```
target/release/subruster
```

## Usage

```bash
subruster <COMMAND> [OPTIONS]
```

### Commands

* `enum` – Enumerate subdomains for a target domain
* `help` – Show help for commands

### Examples

```bash
# Use built-in wordlist
subruster enum -d example.com

# Use custom wordlist
subruster enum -d example.com -w wordlist.txt

# Increase concurrency
subruster enum -d example.com -c 200

# Save results to file
subruster enum -d example.com -o results.txt

# Silent mode (only subdomains, no banner/logs)
subruster enum -d example.com -s
```

## Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.
Do not use it against targets without **explicit permission**.

---

Made with ❤️ in Rust 🦀
