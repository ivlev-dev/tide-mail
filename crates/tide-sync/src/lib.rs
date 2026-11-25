pub mod backend;
pub mod client;
pub mod error;
pub mod session;

pub use backend::{AllowAllAuth, InMemoryBackend, SyncAuth, SyncBackend};
pub use client::{ClientEvent, ClientSession};
pub use error::SyncError;
pub use session::{PROTOCOL_VERSION, ServerSession, error_frame};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use silent_protocol::SilentProto;
    use tide_proto::{
        Cursor, MessageMeta, SyncOperation, change_kind, op_kind,
    };

    use super::*;

    fn setup() -> (
        ServerSession,
        ClientSession,
        Arc<InMemoryBackend>,
        String,
    ) {
        let backend = Arc::new(InMemoryBackend::new());
        let server = ServerSession::new(
            backend.clone(),
            Arc::new(AllowAllAuth),
            "tide-server",
        );
        let (client, hello) = ClientSession::new("device-1", "test");
        let mut server = server;
        let mut client = client;
        let frames = server.handle(hello);
        assert_eq!(client.handle(frames[0].clone()).unwrap().class_name(), "hello");
        let auth = client.auth_frame("alice", "token", "device-1").unwrap();
        let frames = server.handle(auth);
        assert_eq!(client.handle(frames[0].clone()).unwrap().class_name(), "auth");
        backend
            .seed_message(
                "alice",
                MessageMeta {
                    id: "m1".into(),
                    account_id: "alice".into(),
                    mailbox: "INBOX".into(),
                    subject: "Hello".into(),
                    date: 1_700_000_000_000,
                    ..MessageMeta::default()
                },
            )
            .unwrap();
        (server, client, backend, "alice".into())
    }

    trait EventClass {
        fn class_name(&self) -> &'static str;
    }

    impl EventClass for ClientEvent {
        fn class_name(&self) -> &'static str {
            match self {
                ClientEvent::Hello(_) => "hello",
                ClientEvent::Auth(_) => "auth",
                ClientEvent::Changes(_) => "changes",
                ClientEvent::Push(_) => "push",
                ClientEvent::Event(_) => "event",
                ClientEvent::Blob(_) => "blob",
                ClientEvent::Pong(_) => "pong",
                ClientEvent::Error(_) => "error",
            }
        }
    }

    #[test]
    fn pull_changes() {
        let (mut server, mut client, _, _) = setup();
        let request = client.pull_frame_for("alice", 10, None).unwrap();
        let frames = server.handle(request);
        match client.handle(frames[0].clone()).unwrap() {
            ClientEvent::Changes(changes) => {
                assert_eq!(changes.changes.len(), 1);
                assert_eq!(changes.changes[0].change_kind_name(), change_kind::UPSERT);
                assert_eq!(changes.next_cursor, Cursor { lane: 1, seq: 1 });
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    trait ChangeClass {
        fn change_kind_name(&self) -> u32;
    }

    impl ChangeClass for tide_proto::SyncChange {
        fn change_kind_name(&self) -> u32 {
            self.kind
        }
    }

    #[test]
    fn push_is_idempotent_and_pull_sees_it() {
        let (mut server, mut client, _, _) = setup();
        let meta = MessageMeta {
            id: "m2".into(),
            account_id: "alice".into(),
            mailbox: "INBOX".into(),
            subject: "Second".into(),
            ..MessageMeta::default()
        };
        let operation = SyncOperation {
            kind: op_kind::PUT_MESSAGE,
            message_id: "m2".into(),
            flags: 0,
            mailbox: String::new(),
            payload: meta.encode().unwrap(),
        };
        let request = client
            .push_frame("alice", "txn-1", vec![operation.clone()])
            .unwrap();
        let frames = server.handle(request);
        match client.handle(frames[0].clone()).unwrap() {
            ClientEvent::Push(result) => {
                assert_eq!(result.applied, 1);
                assert_eq!(result.cursor.seq, 2);
            }
            other => panic!("unexpected {other:?}"),
        }
        let request = client
            .push_frame("alice", "txn-1", vec![operation])
            .unwrap();
        let frames = server.handle(request);
        match client.handle(frames[0].clone()).unwrap() {
            ClientEvent::Push(result) => assert_eq!(result.applied, 1),
            other => panic!("unexpected {other:?}"),
        }
        let request = client
            .pull_frame_at("alice", Cursor { lane: 1, seq: 0 }, 10, None)
            .unwrap();
        let frames = server.handle(request);
        match client.handle(frames[0].clone()).unwrap() {
            ClientEvent::Changes(changes) => assert_eq!(changes.changes.len(), 2),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn flags_and_delete() {
        let (mut server, mut client, _, _) = setup();
        let flags = SyncOperation {
            kind: op_kind::FLAGS,
            message_id: "m1".into(),
            flags: 1,
            mailbox: String::new(),
            payload: Vec::new(),
        };
        let request = client
            .push_frame("alice", "txn-flags", vec![flags])
            .unwrap();
        let frames = server.handle(request);
        assert!(matches!(
            client.handle(frames[0].clone()).unwrap(),
            ClientEvent::Push(_)
        ));
        let delete = SyncOperation {
            kind: op_kind::DELETE,
            message_id: "m1".into(),
            flags: 0,
            mailbox: String::new(),
            payload: Vec::new(),
        };
        let request = client
            .push_frame("alice", "txn-delete", vec![delete])
            .unwrap();
        let frames = server.handle(request);
        assert!(matches!(
            client.handle(frames[0].clone()).unwrap(),
            ClientEvent::Push(_)
        ));
        let request = client
            .pull_frame_at("alice", Cursor { lane: 1, seq: 0 }, 10, None)
            .unwrap();
        let frames = server.handle(request);
        match client.handle(frames[0].clone()).unwrap() {
            ClientEvent::Changes(changes) => {
                assert_eq!(changes.changes.len(), 2);
                assert_eq!(changes.changes[1].flags, Some(1));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_pull_for_other_account() {
        let (mut server, mut client, _, _) = setup();
        let request = client.pull_frame_for("bob", 10, None).unwrap();
        let frames = server.handle(request);
        match client.handle(frames[0].clone()).unwrap() {
            ClientEvent::Error(error) => assert_eq!(error.code, 401),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn watch_returns_event_or_empty_changes() {
        let (mut server, mut client, backend, _) = setup();
        let request = client.watch_frame("alice", 100).unwrap();
        let frames = server.handle(request);
        assert!(matches!(
            client.handle(frames[0].clone()).unwrap(),
            ClientEvent::Event(_)
        ));
        let request = client.watch_frame("alice", 100).unwrap();
        let frames = server.handle(request);
        assert!(matches!(
            client.handle(frames[0].clone()).unwrap(),
            ClientEvent::Changes(_)
        ));
        backend
            .seed_message(
                "alice",
                MessageMeta {
                    id: "m3".into(),
                    account_id: "alice".into(),
                    ..MessageMeta::default()
                },
            )
            .unwrap();
        let request = client.watch_frame("alice", 100).unwrap();
        let frames = server.handle(request);
        assert!(matches!(
            client.handle(frames[0].clone()).unwrap(),
            ClientEvent::Event(_)
        ));
    }

    #[test]
    fn blob_range() {
        let (mut server, mut client, backend, _) = setup();
        backend.store_blob("alice", "m1", "a1", b"hello world".to_vec());
        let request = client.blob_frame("alice", "m1", "a1", 6, 5).unwrap();
        let frames = server.handle(request);
        match client.handle(frames[0].clone()).unwrap() {
            ClientEvent::Blob(chunk) => {
                assert_eq!(chunk.data, b"world");
                assert!(chunk.eof);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
