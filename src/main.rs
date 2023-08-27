use std::{collections::HashSet, io::Write};

use dotenv::dotenv;
use mikrotik_api::{self};
use regex::Regex;
use retainer::*;
use serde::Deserialize;

use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct Identity {
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct Empty {}

async fn add_address_list(
    api: &mut mikrotik_api::MikrotikAPI<mikrotik_api::Authenticated>,
    name: &str,
) {
    // Replace discord.media to discord.gg in name
    let name = name.replace("discord.media", "discord.gg");

    let params = [
        ("list", "via-CF"),
        ("address", &name),
        ("dynamic", "yes"),
        ("timeout", "1d"),
    ];

    api.generic_array_call::<Empty>("/ip/firewall/address-list/add", Some(&params))
        .await
        .ok();
}

#[tokio::main]
pub async fn main() {
    dotenv().ok();

    // Make sure that MTIK_HOST, MTIK_USER, MTIK_PASS, MTIK_SCRIPT_NAME are set
    let mtik_host = std::env::var("MTIK_HOST").expect("MTIK_HOST not set");
    let mtik_user = std::env::var("MTIK_USER").expect("MTIK_USER not set");
    let mtik_pass = std::env::var("MTIK_PASS").expect("MTIK_PASS not set");
    let match_regex = Regex::new("\\.discord\\.media$").unwrap();

    // Establish connection to Mikrotik
    let conn = mikrotik_api::connect(&mtik_host).await.unwrap();
    let mut api = match conn.authenticate(&mtik_user, &mtik_pass).await {
        Ok(api) => api,
        Err(e) => {
            println!("Auth Error: {:?}", e);
            return;
        }
    };

    let identity = api
        .generic_oneshot_call::<Identity>("/system/identity/print", None)
        .await
        .unwrap();

    println!("Connected to RouterOS: '{}'", identity.name);

    // Create cache to make sure we don't kill the router.
    let cache = Arc::new(Cache::<String, bool>::new());
    let clone = cache.clone();

    // don't forget to monitor your cache to evict entries
    let _monitor =
        tokio::spawn(async move { clone.monitor(4, 0.25, Duration::from_secs(3)).await });

    let devices = pcap::Device::list().expect("device lookup failed");
    println!("Pick a device:");
    for (id, device) in devices.iter().enumerate() {
        // Print device desc
        println!(
            "{:?}. {:?}",
            id,
            device.desc.clone().unwrap_or(device.name.clone())
        );
    }

    // Get user input
    print!("Enter device id: ");
    std::io::stdout().flush().unwrap();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    // Parse input
    let id: usize = input.trim().parse().unwrap();
    let device = &devices[id];

    // Setup Capture
    let mut cap = pcap::Capture::from_device(device.clone())
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    cap.filter("udp src port 53", true).unwrap();

    loop {
        let packet = cap.next_packet().unwrap();

        // Get UDP Payload from packet with etherparse
        let udp_data = etherparse::SlicedPacket::from_ethernet(&packet)
            .unwrap()
            .payload;

        // Parse DNS Packet with simple_dns
        let parsed = simple_dns::Packet::parse(udp_data);

        match parsed {
            Ok(packet) => {
                // Make sure response_code is NoError
                if packet.rcode() != simple_dns::RCODE::NoError {
                    continue;
                }

                // Make sure there is at least one answer
                if packet.answers.len() == 0 {
                    continue;
                }

                let mut answered_domains: HashSet<String> = HashSet::new();

                // Print question qname where qtype is A and has an associated answer
                for question in packet.questions {
                    if question.qtype == simple_dns::QTYPE::TYPE(simple_dns::TYPE::A) {
                        let answers = packet.answers.iter().filter(|a| a.name == question.qname);
                        if answers.count() > 0 {
                            answered_domains.insert(
                                question
                                    .qname
                                    .get_labels()
                                    .iter()
                                    .map(|l| l.to_string())
                                    .collect::<Vec<String>>()
                                    .join("."),
                            );
                        }
                    }
                }

                // Run script for each domain, use cache and don't run for 60s
                for domain in answered_domains {
                    // Make sure domain matches regex
                    if !match_regex.is_match(&domain) {
                        println!("Domain: {} doesn't match regex", domain);
                        continue;
                    }

                    println!("Domain: {}", domain);

                    if cache.get(&domain).await.is_none() {
                        cache
                            .insert(domain.clone(), true, Duration::from_secs(60))
                            .await;
                        let domain_clone = domain.clone();
                        add_address_list(&mut api, &domain_clone).await;
                    }
                }
            }
            Err(e) => {
                // Ignore if InvalidQType
                if matches!(e, simple_dns::SimpleDnsError::InvalidQType(_)) {
                    continue;
                }
                println!("Packet: {:?}", packet);
                println!("Error: {:?}", e);
            }
        }
    }
}
