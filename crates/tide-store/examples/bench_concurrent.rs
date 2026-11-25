use std::time::Instant;

use tide_core::{Address, Message};
use tide_store::{Db, StoreOptions};

fn message(index: usize) -> Message {
    Message {
        id: format!("c{index}"),
        account_id: "alice@example.com".into(),
        mailbox: "INBOX".into(),
        subject: format!("Concurrent {index}"),
        body_text: "invoice payment terms and project update".repeat(20),
        from: vec![Address {
            email: "billing@example.com".into(),
            name: Some("Billing".into()),
        }],
        date: 1_700_000_000_000 + index as i64,
        size: 1024,
        ..Message::default()
    }
}

fn main() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("bench.tide");
    let db = Db::open(
        &path,
        StoreOptions::default()
            .with_data_lanes(8)
            .with_lane_capacity(256 * 1024 * 1024),
    )
    .expect("open");
    let threads = 16;
    let per_thread = 1000;
    let started = Instant::now();
    let mut handles = Vec::new();
    for thread in 0..threads {
        let db = db.clone();
        handles.push(std::thread::spawn(move || {
            for index in 0..per_thread {
                db.append_message_blocking(message(thread * per_thread + index))
                    .expect("append");
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let elapsed = started.elapsed();
    let count = threads * per_thread;
    println!(
        "same-account concurrent messages={count} append={:?} ({:.0}/s) apply_pending={}",
        elapsed,
        count as f64 / elapsed.as_secs_f64(),
        db.index_size()
    );
}
