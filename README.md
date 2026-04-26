# miner-scanner

Async library to scan a LAN and detect common Bitcoin miner.

It probes a subnet and tries to classify devices as:

- `Bitaxe`
- `Antminer`
- `Whatsminer`
- `Avalon`
- `CGMiner-compatible`

The current implementation checks:

- HTTP endpoints on port `80`
- CGMiner-style API on port `4028`

## Example

```rust
use futures_util::StreamExt;
use miner_scanner::{ScanOptions, scan_network};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cidr = "192.168.1.0/24".parse()?;
    let mut miners = scan_network(cidr, ScanOptions::default());

    while let Some(miner) = miners.next().await {
        println!(
            "{} | {:?} | confidence={}",
            miner.addr, miner.family, miner.confidence
        );
    }

    Ok(())
}
```

## License

This project is distributed under the MIT software license – see the [LICENSE](./LICENSE) file for details
