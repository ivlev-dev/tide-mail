use silent_protocol::SilentProto;
use std::time::Instant;
use tide_core::{Address, Message};
use tide_store::ShardedIndex;

fn message(index: usize) -> Message {
    Message {
        id: format!("m{index}"),
        account_id: "alice@example.com".into(),
        mailbox: "INBOX".into(),
        subject: format!("Invoice {index}"),
        body_text: format!("invoice {} payment terms and project update", index).repeat(20),
        from: vec![Address {
            email: "billing@example.com".into(),
            name: Some("Billing".into()),
        }],
        date: 1_700_000_000_000 + index as i64,
        size: 2048,
        ..Message::default()
    }
}

fn main() {
    let count = 5000;
    let messages: Vec<_> = (0..count).map(message).collect();
    let started = Instant::now();
    let mut bytes = 0;
    for message in &messages {
        bytes += message.encode().unwrap().len();
    }
    println!("encode {:?} {} bytes", started.elapsed(), bytes);
    let index = ShardedIndex::new(16);
    let started = Instant::now();
    for message in &messages {
        index.insert(message);
    }
    println!("index {:?}", started.elapsed());
    let started = Instant::now();
    let mut hits = 0;
    for _ in 0..100 {
        hits += index
            .search(
                &tide_store::SearchQuery::new()
                    .account("alice@example.com")
                    .text("invoice"),
            )
            .len();
    }
    println!("search100 {:?} hits={hits}", started.elapsed());
}
