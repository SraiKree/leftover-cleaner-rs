pub mod app;
pub mod metadata;
pub mod leftover;
pub mod error;

// Re-export commonly used types
pub use app::Application;
pub use metadata::AppMetadata;
pub use leftover::{LeftoverItem, LeftoverKind, ConfidenceLevel};
pub use error::{DomainError, ScannerError, ProcessError, CleanError};