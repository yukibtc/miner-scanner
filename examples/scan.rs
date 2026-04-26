use futures_util::StreamExt;
use ipnet::IpNet;
use miner_scanner::{ScanOptions, scan_network};

#[tokio::main]
async fn main() {
    let opts = ScanOptions::default();
    let cidr: IpNet = "192.168.2.0/24".parse().unwrap();

    let mut stream = scan_network(cidr, opts);

    // Scan the network to find miners
    while let Some(miner) = stream.next().await {
        println!("{miner:?}");
    }
}
