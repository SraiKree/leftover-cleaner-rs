use crate::domain::metadata::AppMetadata;
use std::marker::PhantomData;

/// Type-state marker for discovered applications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discovered;

/// Type-state marker for applications being uninstalled
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uninstalling;

/// Type-state marker for scanned applications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scanned;

/// Type-state marker for purged applications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Purged;

/// Application with type-state parameter for compile-time lifecycle enforcement
#[derive(Debug)]
pub struct Application<State> {
    /// Application metadata
    pub metadata: AppMetadata,
    
    /// List of leftover items found for this application
    pub leftovers: Vec<crate::domain::leftover::LeftoverItem>,
    
    /// Type-state marker (compile-time only)
    _state: PhantomData<State>,
}

impl<State> Application<State> {
    /// Create a new application with the given state
    pub fn new(metadata: AppMetadata) -> Self {
        Self {
            metadata,
            leftovers: Vec::new(),
            _state: PhantomData,
        }
    }
    
    /// Add a leftover item to the application
    pub fn add_leftover(&mut self, leftover: crate::domain::leftover::LeftoverItem) {
        self.leftovers.push(leftover);
    }
    
    /// Get the number of leftover items
    pub fn leftover_count(&self) -> usize {
        self.leftovers.len()
    }
}

impl Application<Discovered> {
    /// Transition from Discovered to Uninstalling state
    /// Consumes self to enforce state transition at compile time
    pub fn begin_uninstall(self) -> Application<Uninstalling> {
        Application {
            metadata: self.metadata,
            leftovers: self.leftovers,
            _state: PhantomData,
        }
    }
}

impl Application<Uninstalling> {
    /// Transition from Uninstalling to Scanned state
    /// Consumes self to enforce state transition at compile time
    pub fn complete_scan(self) -> Application<Scanned> {
        Application {
            metadata: self.metadata,
            leftovers: self.leftovers,
            _state: PhantomData,
        }
    }
}

impl Application<Scanned> {
    /// Transition from Scanned to Purged state
    /// Consumes self to enforce state transition at compile time
    pub fn complete_purge(self) -> Application<Purged> {
        Application {
            metadata: self.metadata,
            leftovers: self.leftovers,
            _state: PhantomData,
        }
    }
}

impl Application<Purged> {
    /// Get a summary of the purge operation
    pub fn purge_summary(&self) -> String {
        format!("Purged {} leftover items for {}", self.leftovers.len(), self.metadata.display_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::metadata::AppMetadata;
    use crate::domain::leftover::{LeftoverItem, LeftoverKind, ConfidenceLevel};

    #[test]
    fn test_type_state_transitions() {
        let metadata = AppMetadata {
            display_name: "Test App".to_string(),
            publisher: Some("Test Publisher".to_string()),
            install_location: Some("C:\\Program Files\\TestApp".to_string()),
            uninstall_string: Some("uninstall.exe /S".to_string()),
            display_icon: Some("test.ico".to_string()),
            install_date: None,
            estimated_size: None,
            version: None,
            system_component: false,
        };
        
        // Start with Discovered state
        let discovered_app = Application::<Discovered>::new(metadata.clone());
        
        // Transition to Uninstalling state (consumes self)
        let uninstalling_app = discovered_app.begin_uninstall();
        
        // Transition to Scanned state (consumes self)
        let scanned_app = uninstalling_app.complete_scan();
        
        // Transition to Purged state (consumes self)
        let purged_app = scanned_app.complete_purge();
        
        // Verify the summary
        assert!(purged_app.purge_summary().contains("Purged 0 leftover items for"));
    }
    
    #[test]
    fn test_add_leftover() {
        let metadata = AppMetadata {
            display_name: "Test App".to_string(),
            publisher: Some("Test Publisher".to_string()),
            install_location: Some("C:\\Program Files\\TestApp".to_string()),
            uninstall_string: Some("uninstall.exe /S".to_string()),
            display_icon: Some("test.ico".to_string()),
            install_date: None,
            estimated_size: None,
            version: None,
            system_component: false,
        };
        
        let mut app = Application::<Discovered>::new(metadata);
        
        let leftover = LeftoverItem {
            path: "C:\\Program Files\\TestApp\\leftover.dll".to_string(),
            kind: LeftoverKind::File,
            confidence: ConfidenceLevel::High,
            source: "File system scan".to_string(),
        };
        
        app.add_leftover(leftover);
        assert_eq!(app.leftover_count(), 1);
    }
}