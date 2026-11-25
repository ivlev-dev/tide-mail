use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),
    #[error("повреждённый файл: {0}")]
    Corrupt(String),
    #[error("некорректный батч: {0}")]
    InvalidBatch(String),
    #[error("lane {lane} переполнен: нужно {need} байт, доступно {available}")]
    LaneFull {
        lane: u16,
        need: u64,
        available: u64,
    },
    #[error("lane {lane} остановлен")]
    LaneClosed { lane: u16 },
    #[error("ошибка протокола: {0}")]
    Protocol(#[from] silent_protocol::ProtocolError),
    #[error("ошибка модели: {0}")]
    Model(#[from] tide_core::ModelError),
    #[error("не найдено: {0}")]
    NotFound(String),
    #[error("файл уже открыт другим процессом")]
    Locked,
    #[error("некорректная конфигурация: {0}")]
    Config(String),
    #[error("внутренняя ошибка: {0}")]
    Internal(String),
}

impl StoreError {
    pub fn corrupt(message: impl fmt::Display) -> Self {
        Self::Corrupt(message.to_string())
    }

    pub fn invalid_batch(message: impl fmt::Display) -> Self {
        Self::InvalidBatch(message.to_string())
    }
}
