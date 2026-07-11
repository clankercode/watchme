use std::process::Command;
use std::time::Duration;

fn main() {
    let watchme = std::env::var_os("WATCHME_BIN").expect("WATCHME_BIN");
    let status = Command::new(watchme).status().expect("run bare watchme");
    assert!(status.success(), "bare watchme registration failed");
    println!("fixture-registered");
    loop { std::thread::sleep(Duration::from_secs(1)); }
}
