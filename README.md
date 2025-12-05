# SubRuster 🦀

**Fast, asynchronous, and lightweight subdomain enumeration tool written in Rust.**

SubRuster leverages Rust's asynchronous runtime (`tokio`) and stream buffering (`futures`) to perform high-speed DNS resolution. It is designed to be resource-efficient, pipeline-friendly, and accurate.

## ✨ Features

  * **High Performance:** Uses stream-based concurrency for thousands of lookups per second.
  * **Smart Wildcard Detection:** Automatically detects and filters wildcard (`*.example.com`) DNS records to reduce false positives.
  * **Resource Efficient:** Low memory footprint compared to Python/Go alternatives.
  * **Pipeline Friendly:** Includes a silent mode for easy integration with other tools.

## 📦 Installation

Ensure you have [Rust and Cargo](https://rustup.rs/) installed.

```bash
# Clone the repository
git clone https://github.com/yourusername/subruster.git

# Build the release binary
cd subruster
cargo build --release

# (Optional) Move to path
sudo cp target/release/subruster /usr/local/bin/
```

## 🚀 Usage

```bash
subruster -d <DOMAIN> -w <WORDLIST> [FLAGS]
```

### Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-d`, `--domain` | Target domain to enumerate (e.g., `example.com`) | **Required** |
| `-w`, `--wordlist`| Path to the subdomain wordlist file | **Required** |
| `-c`, `--concurrency` | Number of concurrent worker threads | `100` |
| `--timeout` | DNS query timeout in seconds | `5` |
| `-o`, `--output` | Save valid subdomains to a file | None |
| `-s`, `--silent` | Silent mode (show only found domains) | `false` |

## ⚡ Examples

**Basic enumeration:**

```bash
subruster -d example.com -w wordlist.txt
```

**High-speed scan (500 threads) saving to file:**

```bash
subruster -d google.com -w large_wordlist.txt -c 500 -o results.txt
```

**Pipeline mode (piping to another tool):**

```bash
subruster -d yahoo.com -w wordlist.txt -s | httpx -silent
```

-----

## ⚠️ Disclaimer

This tool is for educational purposes and authorized security testing only. The author is not responsible for any misuse.
