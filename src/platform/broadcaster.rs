//! Thread-Safe Event Broadcasting with DashMap
//!
//! This module provides a lock-free event broadcasting system using DashMap
//! for managing subscribers. It enables multiple consumers to receive events
//! without blocking the event producer.
//!
//! # Features
//!
//! - Lock-free subscription management
//! - Multiple concurrent subscribers
//! - Automatic cleanup of disconnected receivers
//! - Zero-copy event cloning for subscribers
//! - Thread-safe without global locks
//!
//! # Usage
//!
//! ```rust,ignore
//! use witnessd_core::platform::broadcaster::EventBroadcaster;
//!
//! let broadcaster: EventBroadcaster<KeystrokeEvent> = EventBroadcaster::new();
//!
//! // Subscribe (returns subscription ID and receiver)
//! let (id, rx) = broadcaster.subscribe();
//!
//! // Broadcast event to all subscribers
//! broadcaster.broadcast(event);
//!
//! // Unsubscribe when done
//! broadcaster.unsubscribe(id);
//! ```

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Subscription identifier type.
pub type SubscriptionId = u64;

/// Thread-safe event broadcaster using DashMap.
///
/// Allows multiple subscribers to receive events without blocking the producer.
/// Uses unbounded channels to prevent backpressure on the producer.
pub struct EventBroadcaster<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Map of subscription IDs to senders
    subscribers: DashMap<SubscriptionId, UnboundedSender<T>>,
    /// Counter for generating unique subscription IDs
    next_id: AtomicU64,
    /// Count of successful broadcasts
    broadcast_count: AtomicU64,
    /// Count of failed sends (disconnected receivers)
    failed_sends: AtomicU64,
}

impl<T> EventBroadcaster<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Create a new event broadcaster.
    pub fn new() -> Self {
        Self {
            subscribers: DashMap::new(),
            next_id: AtomicU64::new(0),
            broadcast_count: AtomicU64::new(0),
            failed_sends: AtomicU64::new(0),
        }
    }

    /// Subscribe to receive events.
    ///
    /// Returns a subscription ID (for unsubscribing) and a receiver channel.
    pub fn subscribe(&self) -> (SubscriptionId, UnboundedReceiver<T>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::unbounded_channel();
        self.subscribers.insert(id, tx);
        (id, rx)
    }

    /// Unsubscribe from events.
    ///
    /// Removes the subscriber with the given ID. Safe to call multiple times.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.subscribers.remove(&id);
    }

    /// Broadcast an event to all subscribers.
    ///
    /// Automatically removes disconnected subscribers.
    pub fn broadcast(&self, event: T) {
        self.broadcast_count.fetch_add(1, Ordering::Relaxed);

        // Collect IDs of failed sends for removal
        let mut failed_ids = Vec::new();

        for entry in self.subscribers.iter() {
            let id = *entry.key();
            let tx = entry.value();

            if tx.send(event.clone()).is_err() {
                // Receiver dropped, mark for removal
                failed_ids.push(id);
            }
        }

        // Remove failed subscribers
        for id in failed_ids {
            self.subscribers.remove(&id);
            self.failed_sends.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get the current number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Get the total number of broadcasts made.
    pub fn broadcast_count(&self) -> u64 {
        self.broadcast_count.load(Ordering::Relaxed)
    }

    /// Get the total number of failed sends (disconnected receivers).
    pub fn failed_sends(&self) -> u64 {
        self.failed_sends.load(Ordering::Relaxed)
    }

    /// Clear all subscribers.
    pub fn clear(&self) {
        self.subscribers.clear();
    }

    /// Check if there are any active subscribers.
    pub fn has_subscribers(&self) -> bool {
        !self.subscribers.is_empty()
    }
}

impl<T> Default for EventBroadcaster<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Synchronous Broadcaster (std::sync::mpsc)
// =============================================================================

/// Synchronous event broadcaster using std::sync::mpsc.
///
/// Use this when you don't need async/tokio and want to use synchronous channels.
pub struct SyncEventBroadcaster<T>
where
    T: Clone + Send + 'static,
{
    subscribers: DashMap<SubscriptionId, std::sync::mpsc::Sender<T>>,
    next_id: AtomicU64,
    broadcast_count: AtomicU64,
    failed_sends: AtomicU64,
}

impl<T> SyncEventBroadcaster<T>
where
    T: Clone + Send + 'static,
{
    /// Create a new synchronous event broadcaster.
    pub fn new() -> Self {
        Self {
            subscribers: DashMap::new(),
            next_id: AtomicU64::new(0),
            broadcast_count: AtomicU64::new(0),
            failed_sends: AtomicU64::new(0),
        }
    }

    /// Subscribe to receive events.
    ///
    /// Returns a subscription ID and a synchronous receiver.
    pub fn subscribe(&self) -> (SubscriptionId, std::sync::mpsc::Receiver<T>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = std::sync::mpsc::channel();
        self.subscribers.insert(id, tx);
        (id, rx)
    }

    /// Unsubscribe from events.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.subscribers.remove(&id);
    }

    /// Broadcast an event to all subscribers.
    pub fn broadcast(&self, event: T) {
        self.broadcast_count.fetch_add(1, Ordering::Relaxed);

        let mut failed_ids = Vec::new();

        for entry in self.subscribers.iter() {
            let id = *entry.key();
            let tx = entry.value();

            if tx.send(event.clone()).is_err() {
                failed_ids.push(id);
            }
        }

        for id in failed_ids {
            self.subscribers.remove(&id);
            self.failed_sends.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get the current number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Get the total number of broadcasts made.
    pub fn broadcast_count(&self) -> u64 {
        self.broadcast_count.load(Ordering::Relaxed)
    }

    /// Get the total number of failed sends.
    pub fn failed_sends(&self) -> u64 {
        self.failed_sends.load(Ordering::Relaxed)
    }

    /// Clear all subscribers.
    pub fn clear(&self) {
        self.subscribers.clear();
    }

    /// Check if there are any active subscribers.
    pub fn has_subscribers(&self) -> bool {
        !self.subscribers.is_empty()
    }
}

impl<T> Default for SyncEventBroadcaster<T>
where
    T: Clone + Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Clone, Debug, PartialEq)]
    struct TestEvent {
        value: u32,
    }

    #[tokio::test]
    async fn test_broadcaster_single_subscriber() {
        let broadcaster = EventBroadcaster::new();
        let (id, mut rx) = broadcaster.subscribe();

        broadcaster.broadcast(TestEvent { value: 42 });

        let event = rx.recv().await.unwrap();
        assert_eq!(event.value, 42);

        broadcaster.unsubscribe(id);
    }

    #[tokio::test]
    async fn test_broadcaster_multiple_subscribers() {
        let broadcaster = EventBroadcaster::new();

        let (id1, mut rx1) = broadcaster.subscribe();
        let (id2, mut rx2) = broadcaster.subscribe();
        let (id3, mut rx3) = broadcaster.subscribe();

        assert_eq!(broadcaster.subscriber_count(), 3);

        broadcaster.broadcast(TestEvent { value: 100 });

        assert_eq!(rx1.recv().await.unwrap().value, 100);
        assert_eq!(rx2.recv().await.unwrap().value, 100);
        assert_eq!(rx3.recv().await.unwrap().value, 100);

        broadcaster.unsubscribe(id1);
        broadcaster.unsubscribe(id2);
        broadcaster.unsubscribe(id3);

        assert_eq!(broadcaster.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn test_broadcaster_automatic_cleanup() {
        let broadcaster = EventBroadcaster::new();

        let (_, rx1) = broadcaster.subscribe();
        let (id2, mut rx2) = broadcaster.subscribe();

        // Drop first receiver
        drop(rx1);

        // Broadcast should clean up the dropped receiver
        broadcaster.broadcast(TestEvent { value: 1 });

        // Second subscriber should still work
        assert_eq!(rx2.recv().await.unwrap().value, 1);

        // Only one subscriber should remain
        assert_eq!(broadcaster.subscriber_count(), 1);
        assert_eq!(broadcaster.failed_sends(), 1);

        broadcaster.unsubscribe(id2);
    }

    #[tokio::test]
    async fn test_broadcaster_statistics() {
        let broadcaster = EventBroadcaster::new();
        let (_, _rx) = broadcaster.subscribe();

        for i in 0..10 {
            broadcaster.broadcast(TestEvent { value: i });
        }

        assert_eq!(broadcaster.broadcast_count(), 10);
    }

    #[test]
    fn test_sync_broadcaster_single_subscriber() {
        let broadcaster = SyncEventBroadcaster::new();
        let (id, rx) = broadcaster.subscribe();

        broadcaster.broadcast(TestEvent { value: 42 });

        let event = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(event.value, 42);

        broadcaster.unsubscribe(id);
    }

    #[test]
    fn test_sync_broadcaster_multiple_subscribers() {
        let broadcaster = SyncEventBroadcaster::new();

        let (id1, rx1) = broadcaster.subscribe();
        let (id2, rx2) = broadcaster.subscribe();

        assert_eq!(broadcaster.subscriber_count(), 2);

        broadcaster.broadcast(TestEvent { value: 100 });

        assert_eq!(rx1.recv_timeout(Duration::from_secs(1)).unwrap().value, 100);
        assert_eq!(rx2.recv_timeout(Duration::from_secs(1)).unwrap().value, 100);

        broadcaster.unsubscribe(id1);
        broadcaster.unsubscribe(id2);
    }

    #[test]
    fn test_sync_broadcaster_cleanup() {
        let broadcaster = SyncEventBroadcaster::new();

        let (_, rx1) = broadcaster.subscribe();
        let (id2, rx2) = broadcaster.subscribe();

        drop(rx1);

        broadcaster.broadcast(TestEvent { value: 1 });

        assert_eq!(rx2.recv_timeout(Duration::from_secs(1)).unwrap().value, 1);
        assert_eq!(broadcaster.subscriber_count(), 1);

        broadcaster.unsubscribe(id2);
    }

    #[test]
    fn test_broadcaster_thread_safety() {
        use std::thread;

        let broadcaster = std::sync::Arc::new(SyncEventBroadcaster::new());
        let receivers: Vec<_> = (0..10).map(|_| broadcaster.subscribe()).collect();

        // Spawn multiple threads to broadcast
        let handles: Vec<_> = (0..5)
            .map(|t| {
                let bc = broadcaster.clone();
                thread::spawn(move || {
                    for i in 0..100 {
                        bc.broadcast(TestEvent { value: t * 100 + i });
                    }
                })
            })
            .collect();

        // Wait for all broadcasts
        for h in handles {
            h.join().unwrap();
        }

        // Each receiver should have received 500 events (5 threads * 100 events)
        for (_, rx) in receivers {
            let mut count = 0;
            while rx.try_recv().is_ok() {
                count += 1;
            }
            assert_eq!(count, 500);
        }
    }
}
