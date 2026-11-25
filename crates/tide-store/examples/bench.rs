use std::time::Instant;

use tide_core::{Address, Message};
use tide_store::{Db, SearchQuery, StoreOptions};

fn main() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("bench.tide");
    let db = Db::open(
        &path,
        StoreOptions::default()
            .with_data_lanes(8)
            .with_lane_capacity(64 * 1024 * 1024),
    )
    .expect("open");
    let started = Instant::now();
    let count = 5_000;
    for index in 0..count {
        let body = format!("invoice {} payment terms and project update", index).repeat(20);
        db.append_message_blocking(Message {
            id: format!("m{index}"),
            account_id: "alice@example.com".into(),
            mailbox: "INBOX".into(),
            subject: format!("Invoice {index}"),
            body_text: body,
            from: vec![Address {
                email: "billing@example.com".into(),
                name: Some("Billing".into()),
            }],
            date: 1_700_000_000_000 + index as i64,
            size: 2048,
            ..Message::default()
        })
        .expect("append");
    }
    let append_elapsed = started.elapsed();
    let snapshot = Instant::now();
    futures::executor::block_on(db.flush()).expect("flush");
    let snapshot_elapsed = snapshot.elapsed();
    let search = Instant::now();
    let mut hits = 0;
    for _ in 0..100 {
        hits += db
            .search(
                &SearchQuery::new()
                    .account("alice@example.com")
                    .text("invoice"),
            )
            .len();
    }
    let search_elapsed = search.elapsed();
    drop(db);
    let reopen = Instant::now();
    let db = Db::open(
        &path,
        StoreOptions::default()
            .with_data_lanes(8)
            .with_lane_capacity(64 * 1024 * 1024),
    )
    .expect("reopen");
    let reopen_elapsed = reopen.elapsed();
    println!(
        "messages={count} append={:?} ({:.0}/s) snapshot={:?} search100={:?} hits={hits} reopen={:?}",
        append_elapsed,
        count as f64 / append_elapsed.as_secs_f64(),
        snapshot_elapsed,
        search_elapsed,
        reopen_elapsed
    );
    drop(db);
}
