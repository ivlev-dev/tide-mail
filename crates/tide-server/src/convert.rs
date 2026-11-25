use tide_core::{Address as CoreAddress, Message};
use tide_proto::{
    Address, AttachmentMeta, MessageBody, MessageMeta, SyncChange, change_kind as proto_kind,
};
use tide_store::{ChangeEntry, change::kind as store_kind};

pub fn address(address: &CoreAddress) -> Address {
    Address {
        email: address.email.clone(),
        name: address.name.clone(),
    }
}

pub fn message_to_meta(message: &Message) -> MessageMeta {
    MessageMeta {
        id: message.id.clone(),
        account_id: message.account_id.clone(),
        mailbox: message.mailbox.clone(),
        thread_id: message.thread_id.clone(),
        message_id: message.message_id.clone(),
        subject: message.subject.clone(),
        from: message.from.iter().map(address).collect(),
        to: message.to.iter().map(address).collect(),
        cc: message.cc.iter().map(address).collect(),
        date: message.date,
        flags: message.flags,
        size: message.size,
        snippet: message.body_text.chars().take(160).collect(),
    }
}

pub fn message_to_body(message: &Message) -> MessageBody {
    MessageBody {
        id: message.id.clone(),
        text: message.body_text.clone(),
        html: message.body_html.clone(),
        attachments: message
            .attachments
            .iter()
            .enumerate()
            .map(|(index, attachment)| AttachmentMeta {
                id: index.to_string(),
                filename: attachment.filename.clone(),
                content_type: attachment.content_type.clone(),
                size: attachment.size,
                inline: false,
            })
            .collect(),
        raw: message.raw.clone(),
    }
}

pub fn change_to_meta(entry: &ChangeEntry) -> MessageMeta {
    MessageMeta {
        id: entry.message_id.clone(),
        account_id: entry.account_id.clone(),
        mailbox: entry.mailbox.clone(),
        thread_id: entry.thread_id.clone(),
        message_id: entry.message_id_header.clone(),
        subject: entry.subject.clone(),
        from: entry.from.iter().map(address).collect(),
        to: entry.to.iter().map(address).collect(),
        cc: entry.cc.iter().map(address).collect(),
        date: entry.date,
        flags: entry.flags,
        size: entry.size,
        snippet: entry.snippet.clone(),
    }
}

pub fn change_to_sync(entry: &ChangeEntry) -> SyncChange {
    let kind = match entry.kind {
        store_kind::UPSERT => proto_kind::UPSERT,
        store_kind::DELETE => proto_kind::DELETE,
        store_kind::FLAGS => proto_kind::FLAGS,
        store_kind::MOVE => proto_kind::MOVE,
        _ => proto_kind::UPSERT,
    };
    SyncChange {
        kind,
        message_id: entry.message_id.clone(),
        seq: entry.seq,
        meta: if entry.deleted {
            None
        } else {
            Some(change_to_meta(entry))
        },
        flags: if kind == proto_kind::FLAGS {
            Some(entry.flags)
        } else {
            None
        },
        mailbox: if kind == proto_kind::MOVE {
            Some(entry.mailbox.clone())
        } else {
            None
        },
        deleted: entry.deleted,
        payload: Vec::new(),
    }
}
