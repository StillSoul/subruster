use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Parser)]
#[clap(
    name = "subruster",
    version = "1.0.0",
    author = "YourName <you@example.com>",
    about = "Fast and lightweight subdomain enumeration tool written in Rust 🦀",
    long_about = r#"
SubRuster — это инструмент для перебора поддоменов с использованием DNS-запросов.

Особенности:
  • Поддержка wordlist (или встроенного словаря по умолчанию)
  • Настройка количества потоков (concurrency)
  • Таймаут для DNS-запросов
  • Игнорирование/включение wildcard-субдоменов
  • Сохранение результатов в файл
  • Тихий режим (silent mode)

Примеры:
  # Использовать встроенный wordlist
  subruster enum -d example.com

  # Использовать кастомный wordlist
  subruster enum -d example.com -w wordlist.txt

  # Увеличить количество потоков
  subruster enum -d example.com -c 200

  # Сохранить результаты в файл
  subruster enum -d example.com -o results.txt

  # В тихом режиме (только результаты)
  subruster enum -d example.com -s
"#
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Enumerate subdomains for a target domain
    #[clap(
        about = "Перебор субдоменов",
        long_about = r#"
Перебирает поддомены для указанного домена.

По умолчанию используется встроенный словарь, 
но можно указать свой wordlist-файл.
"#
    )]
    Enum(EnumArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct EnumArgs {
    /// Target domain to enumerate
    #[clap(
        short,
        long,
        value_name = "DOMAIN",
        help = "Целевой домен (например: example.com)"
    )]
    pub domain: String,

    /// Path to wordlist file
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Путь к wordlist-файлу (по умолчанию встроенный словарь)"
    )]
    pub wordlist: Option<String>,

    /// Number of concurrent workers
    #[clap(
        short,
        long,
        default_value_t = 100,
        help = "Количество конкурентных задач (по умолчанию 100)"
    )]
    pub concurrency: usize,

    /// Include wildcard subdomains
    #[clap(long, help = "Включать даже wildcard-субдомены")]
    pub include_wildcard: bool,

    /// Timeout for DNS requests (seconds)
    #[clap(
        long,
        default_value_t = 5,
        value_name = "SECONDS",
        help = "Таймаут DNS-запроса в секундах (по умолчанию 5)"
    )]
    pub timeout: u64,

    /// Output results to file
    #[clap(short, long, value_name = "FILE", help = "Сохранить результаты в файл")]
    pub output: Option<String>,

    /// Silent mode (only output results)
    #[clap(short, long, help = "Тихий режим (вывод только результатов)")]
    pub silent: bool,
}
#[derive(Debug, Clone)]
struct SubdomainResult {
    subdomain: String,
    ips: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Enum(args) => {
            run_enum(args).await?;
        }
    }

    Ok(())
}

async fn run_enum(args: &EnumArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !args.silent {
        print_banner();
        println!("{} {}", "Target:".bold(), args.domain.cyan());
        match &args.wordlist {
            Some(path) => println!("{} {}", "Wordlist:".bold(), path.cyan()),
            None => println!("{} {}", "Wordlist:".bold(), "built-in".cyan()),
        }
        println!(
            "{} {}",
            "Concurrency:".bold(),
            args.concurrency.to_string().yellow()
        );
        println!();
    }

    // Загружаем вордлист
    let subdomains = match &args.wordlist {
        Some(path) => load_wordlist_from_file(path)?,
        None => load_builtin_wordlist(),
    };

    if !args.silent {
        println!(
            "{} {} subdomains loaded",
            "Loaded:".bold(),
            subdomains.len().to_string().yellow()
        );
        println!();
    }

    // Создаем DNS резолвер
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        .expect("Failed to create DNS resolver");

    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let results = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let found_subdomains = Arc::new(tokio::sync::Mutex::new(HashSet::new()));

    let mut handles = vec![];

    // Клонируем необходимые значения для замыкания
    let domain = args.domain.clone();
    let timeout_duration = args.timeout;
    let silent = args.silent;
    let include_wildcard = args.include_wildcard;

    for sub in subdomains {
        let full_domain = format!("{}.{}", sub, domain);
        let resolver = resolver.clone();
        let semaphore = semaphore.clone();
        let results = results.clone();
        let found_subdomains = found_subdomains.clone();
        let domain_clone = domain.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            match timeout(
                Duration::from_secs(timeout_duration),
                resolver.lookup_ip(full_domain.as_str()),
            )
            .await
            {
                Ok(Ok(lookup)) => {
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();

                    if !ips.is_empty() {
                        let is_wildcard =
                            check_wildcard(&resolver, &domain_clone, timeout_duration)
                                .await
                                .unwrap_or(false);

                        if !is_wildcard || include_wildcard {
                            let result = SubdomainResult {
                                subdomain: full_domain.clone(),
                                ips: ips.clone(),
                            };

                            {
                                let mut results_lock = results.lock().await;
                                results_lock.push(result);
                            }

                            {
                                let mut found_lock = found_subdomains.lock().await;
                                if found_lock.insert(full_domain.clone()) {
                                    if !silent {
                                        println!(
                                            "{} {} ({})",
                                            "✓".green().bold(),
                                            full_domain.bold().green(),
                                            ips.join(", ").dimmed()
                                        );
                                    } else {
                                        println!("{}", full_domain);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {
                    // ignore errors / timeouts
                }
            }
        });

        handles.push(handle);
    }

    // Ждем завершения всех задач
    for handle in handles {
        handle.await?;
    }

    if !args.silent {
        println!();
        println!("{}", "Enumeration completed successfully!".green().bold());
    }

    // Сохраняем результаты в файл если указан
    if let Some(output_file) = &args.output {
        save_results(&results, output_file).await?;
        if !args.silent {
            let results_lock = results.lock().await;
            println!(
                "{} {} results saved to {}",
                "Saved:".bold(),
                results_lock.len().to_string().yellow(),
                output_file.cyan()
            );
        }
    }

    Ok(())
}

fn load_wordlist_from_file(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut subdomains = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            subdomains.push(line.to_string());
        }
    }

    Ok(subdomains)
}

fn load_builtin_wordlist() -> Vec<String> {
    let builtin_words = r#"www
mail
ftp
admin
api
blog
dev
test
shop
forum
m
mobile
support
news
chat
cdn
status
docs
wiki
app
secure
login
portal
beta
stage
vpn
remote
cms
git
jenkins
ci
staging
prod
img
image
video
files
download
media
static
assets
auth
oauth
cloud
backup
db
sql
mysql
postgres
redis
monitor
stats
analytics
crm
erp
hr
finance
pay
payment
cart
store
help
kb
knowledge
service
tools
old
new
demo
sandbox
temp
tmp
internal
private
public
external
cache
edge
origin
gateway
proxy
lb
loadbalancer
firewall
dns
smtp
pop
imap
sip
ldap
intranet
extranet
corp
enterprise
hq
office
work
home
lab
devops
ops
sys
system
it
info
data
reports
dashboard
ui
ux
design
marketing
sales
legal
compliance
security
audit
log
logs
monitoring
alert
notification
email
sms
webhook
event
calendar
booking
ticket
account
profile
user
users
customer
client
partner
vendor
supplier
affiliate
referral
promo
promotion
deal
offer
coupon
gift
survey
poll
quiz
contest
game
play
fun
entertainment
music
stream
live
radio
podcast
tv
show
episode
series
season
anime
manga
comic
book
read
library
archive
upload
share
drive
drop
box
storage
sync
transfer
send
inbox
outbox
draft
trash
spam
junk
favorite
starred
important
priority
urgent
task
todo
list
project
team
group
community
board
message
messaging
voice
voip
call
conference
meeting
room
virtual
vr
ar
metaverse
nft
crypto
blockchain
wallet
exchange
trade
market
marketplace"#;

    builtin_words.lines().map(|s| s.to_string()).collect()
}

async fn check_wildcard(
    resolver: &TokioAsyncResolver,
    domain: &str,
    timeout_duration: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Генерируем случайное число для тестового субдомена
    let random_num = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();

    let test_subdomain = format!("subruster-test-{}", random_num);
    let full_domain = format!("{}.{}", test_subdomain, domain);

    match timeout(
        Duration::from_secs(timeout_duration),
        resolver.lookup_ip(full_domain.as_str()),
    )
    .await
    {
        Ok(Ok(lookup)) => Ok(lookup.iter().count() > 0),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false),
    }
}

async fn save_results(
    results: &Arc<tokio::sync::Mutex<Vec<SubdomainResult>>>,
    filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::Write;

    let results_lock = results.lock().await;
    let mut file = File::create(filename)?;

    for result in results_lock.iter() {
        writeln!(file, "{}", result.subdomain)?;
    }

    Ok(())
}

fn print_banner() {
    println!(
        "{}",
        r#"
  _________    ___.  __________                __                
 /   _____/__ _\_ |__\______   \__ __  _______/  |_  ___________ 
 \_____  \|  |  \ __ \|       _/  |  \/  ___/\   __\/ __ \_  __ \
 /        \  |  / \_\ \    |   \  |  /\___ \  |  | \  ___/|  | \/
/_______  /____/|___  /____|_  /____//____  > |__|  \___  >__|   
        \/          \/       \/           \/            \/                                                 
    Subdomain Enumeration Tool
    "#
        .bold()
        .blue()
    );
}
