use std::sync::Arc;

use crossbeam_channel::{Sender, unbounded};
use tide_store::Db;

use crate::virus_scan::VirusScanner;

#[derive(Debug, Clone)]
pub struct ScanTask {
    pub message_id: String,
    pub account_id: String,
    pub from_quarantine: bool,
}

pub struct ScanQueue {
    tx: Sender<ScanTask>,
}

impl ScanQueue {
    pub fn start(
        db: Db,
        scanner: Arc<VirusScanner>,
        quarantine: String,
        infected: String,
    ) -> Arc<Self> {
        let (tx, rx) = unbounded::<ScanTask>();
        let initial = db
            .message_ids()
            .into_iter()
            .filter_map(|id| {
                let message = db.get_message(&id).ok().flatten()?;
                (message.mailbox == quarantine).then_some(ScanTask {
                    message_id: id,
                    account_id: message.account_id,
                    from_quarantine: true,
                })
            })
            .collect::<Vec<_>>();
        std::thread::Builder::new()
            .name("tide-antivirus".into())
            .spawn(move || {
                for task in initial {
                    process(&db, &scanner, infected.as_str(), task);
                }
                while let Ok(task) = rx.recv() {
                    process(&db, &scanner, infected.as_str(), task);
                }
            })
            .expect("antivirus worker");
        Arc::new(Self { tx })
    }

    pub fn enqueue(&self, message_id: String, account_id: String, from_quarantine: bool) -> bool {
        self.tx
            .send(ScanTask {
                message_id,
                account_id,
                from_quarantine,
            })
            .is_ok()
    }

    pub fn rescan_all(&self, db: &Db) -> usize {
        let mut queued = 0;
        for id in db.message_ids() {
            if let Ok(Some(message)) = db.get_message(&id) {
                if self.enqueue(id, message.account_id, message.mailbox == "Quarantine") {
                    queued += 1;
                }
            }
        }
        queued
    }
}

fn process(db: &Db, scanner: &VirusScanner, infected: &str, task: ScanTask) {
    let Ok(Some(message)) = db.get_message(&task.message_id) else {
        return;
    };
    match scanner.scan(&message.raw) {
        Ok(()) => {
            if task.from_quarantine {
                let _ = futures::executor::block_on(db.move_message(
                    &task.message_id,
                    &task.account_id,
                    "INBOX",
                ));
            }
        }
        Err(error) => {
            eprintln!("antivirus: {} is infected: {error}", task.message_id);
            let _ = futures::executor::block_on(db.ensure_default_folders(&task.account_id));
            let _ = futures::executor::block_on(db.move_message(
                &task.message_id,
                &task.account_id,
                infected,
            ));
        }
    }
}
