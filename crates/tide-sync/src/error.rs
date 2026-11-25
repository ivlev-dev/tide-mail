use tide_proto::FrameError;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("ошибка кадра: {0}")]
    Frame(#[from] FrameError),
    #[error("ошибка протокола: {0}")]
    Protocol(#[from] silent_protocol::ProtocolError),
    #[error("неавторизован: {0}")]
    Unauthorized(String),
    #[error("неверное состояние сессии: {0}")]
    InvalidState(String),
    #[error("ошибка backend: {0}")]
    Backend(String),
    #[error("неизвестный тип кадра: {0}")]
    UnknownFrame(u8),
}
