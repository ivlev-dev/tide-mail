pub mod address;
pub mod client;
pub mod command;
pub mod config;
pub mod reply;
pub mod session;

pub use client::SmtpClient;
pub use command::{Command, MailCommand, RcptCommand, parse_command};
pub use config::{AuthMechanism, SmtpConfig};
pub use reply::{Reply, SmtpError};
pub use session::{Action, Envelope, SmtpSession};
