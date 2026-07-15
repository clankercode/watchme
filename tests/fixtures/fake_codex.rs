use std::os::unix::process::CommandExt as _;
use std::process::Command;
use std::time::Duration;

fn main() {
    let watchme = std::env::var_os("WATCHME_BIN").expect("WATCHME_BIN");
    let mut command = Command::new(watchme);
    if std::env::var_os("WATCHME_ISOLATE_PROCESS_GROUP").is_some() {
        command.process_group(0);
    }
    let status = command.status().expect("run bare watchme");
    assert!(status.success(), "bare watchme registration failed");
    println!("fixture-registered");
    loop { std::thread::sleep(Duration::from_secs(1)); }
}
