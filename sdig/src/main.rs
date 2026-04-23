mod utils;

use std::net::UdpSocket;
use std::time::Duration;
use std::time::Instant;

use dns_rs::dns::message::DnsMessage;
use dns_rs::dns::records::{DnsClass, DnsType};
use dns_rs::wire;

use crate::utils::{format_request, format_response};

fn print_help() {
    println!(
        r#"sdig - simple DNS client
Usage:
  sdig [@server] <name> [type] [class] [+rec|+norec]
Examples:
  sdig example.com
  sdig example.com A
  sdig @8.8.8.8 example.com AAAA
  sdig example.com TXT +norec
Options:
  -h, --help     Show this help
  -v             Show version
"#
    );
}

fn print_version() {
    println!("sdig {}", env!("CARGO_PKG_VERSION"));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    if raw_args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        std::process::exit(0);
    }

    if raw_args.iter().any(|a| a == "-v") {
        print_version();
        std::process::exit(0);
    }

    // parse_args
    let parsed = match parse_args(&raw_args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", e);
            println!();
            print_help();
            std::process::exit(1);
        }
    };
    let query = DnsMessage::new_query(&parsed.name.unwrap(), parsed.qtype, parsed.recursion);

    let mut writer = wire::Writer::new();
    query.encode(&mut writer)?;
    let packet = writer.into_inner();

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    let start = Instant::now();
    socket.send_to(&packet, parsed.server.unwrap())?;

    let mut buf = [0u8; 512];
    let (size, from) = socket.recv_from(&mut buf)?;
    let elapsed = start.elapsed();

    print!("{}", format_request(&query));
    let response = DnsMessage::decode(&buf[..size])?;
    println!("{}", format_response(&response));
    println!(
        "received {} bytes from {} in {} ms",
        size,
        from,
        elapsed.as_millis()
    );
    Ok(())
}

//---------------------------------------------------------------
// Args
//---------------------------------------------------------------
struct Args {
    server: Option<String>,
    name: Option<String>,
    qtype: DnsType,
    qclass: DnsClass,
    recursion: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            server: Some(String::from("8.8.8.8:53")),
            name: None,
            qtype: DnsType::A,
            qclass: DnsClass::Internet,
            recursion: true,
        }
    }
}

fn parse_args<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut out = Args::default();

    for arg in args {
        let arg = arg.as_ref();

        // @server
        if let Some(server) = arg.strip_prefix('@') {
            if server.is_empty() {
                return Err("missing server after '@'".to_string());
            }

            let server = if has_port(server) {
                server.to_string()
            } else {
                format!("{}:53", server)
            };

            out.server = Some(server);

            continue;
        }

        let arg_lc = arg.to_ascii_lowercase();

        match arg_lc.as_str() {
            "+rec" => {
                out.recursion = true;
                continue;
            }
            "+norec" => {
                out.recursion = false;
                continue;
            }
            "a" => {
                out.qtype = DnsType::A;
                continue;
            }
            "aaaa" => {
                out.qtype = DnsType::AAAA;
                continue;
            }
            "txt" => {
                out.qtype = DnsType::TXT;
                continue;
            }
            "mx" => {
                out.qtype = DnsType::MX;
                continue;
            }
            "ns" => {
                out.qtype = DnsType::NS;
                continue;
            }
            "in" => {
                out.qclass = DnsClass::Internet;
                continue;
            }
            _ => {}
        }

        // name
        if out.name.is_none() {
            out.name = Some(arg.to_string());
        } else {
            return Err(format!("unexpected extra argument: {}", arg));
        }
    }

    if out.name.is_none() {
        return Err("missing query name".to_string());
    }

    Ok(out)
}

fn has_port(s: &str) -> bool {
    if let Some(idx) = s.rfind(':') {
        return s[idx + 1..].chars().all(|c| c.is_ascii_digit());
    }
    false
}
