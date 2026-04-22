mod utils;

use std::net::UdpSocket;
use std::time::Duration;

use dns_rs::dns::message::DnsMessage;
use dns_rs::dns::records::DnsType;
use dns_rs::wire;

use crate::utils::format_request;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dns_type = DnsType::A;
    let query = DnsMessage::new_query("www.google.com", dns_type, true);

    let mut writer = wire::Writer::new();
    query.encode(&mut writer)?;
    let packet = writer.into_inner();

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    // Google Public DNS
    socket.send_to(&packet, "8.8.8.8:53")?;

    let mut buf = [0u8; 512];
    let (size, from) = socket.recv_from(&mut buf)?;

    println!("{}", format_request(&query));
    println!("received {} bytes from {}", size, from);
    let response = DnsMessage::decode(&buf[..size])?;
    println!("{:#?}", response);

    Ok(())
}
