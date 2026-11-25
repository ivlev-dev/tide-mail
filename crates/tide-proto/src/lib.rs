pub mod api;
pub mod frame;
pub mod sync;

pub use api::*;
pub use frame::{Frame, FrameError, MAX_FRAME_SIZE};
pub use sync::*;

#[cfg(test)]
mod tests {
    use super::*;
    use silent_protocol::SilentProto;

    #[test]
    fn api_roundtrip() {
        let request = SearchRequest {
            account_id: "alice".into(),
            query: "invoice 2026".into(),
            subject: Some("invoice".into()),
            body: None,
            from: None,
            mailbox: Some("INBOX".into()),
            include_deleted: false,
            limit: 50,
            offset: 0,
        };
        let bytes = request.encode().unwrap();
        let restored = SearchRequest::decode(&bytes).unwrap();
        assert_eq!(restored, request);
    }

    #[test]
    fn sync_roundtrip() {
        let changes = SyncChanges {
            next_cursor: Cursor { lane: 2, seq: 42 },
            changes: vec![SyncChange {
                kind: change_kind::UPSERT,
                message_id: "m1".into(),
                seq: 42,
                meta: Some(MessageMeta {
                    id: "m1".into(),
                    account_id: "alice".into(),
                    subject: "Hello".into(),
                    from: vec![Address {
                        email: "a@example.com".into(),
                        name: Some("A".into()),
                    }],
                    date: 1_700_000_000_000,
                    ..MessageMeta::default()
                }),
                flags: None,
                mailbox: None,
                deleted: false,
                payload: vec![],
            }],
            has_more: false,
        };
        let bytes = changes.encode().unwrap();
        let restored = SyncChanges::decode(&bytes).unwrap();
        assert_eq!(restored, changes);
    }

    #[test]
    fn error_roundtrip() {
        let error = ErrorResponse {
            code: error_code::UNAUTHORIZED,
            message: "bad token".into(),
            retryable: false,
        };
        assert_eq!(
            ErrorResponse::decode(&error.encode().unwrap()).unwrap(),
            error
        );
    }
}
