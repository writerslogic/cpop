// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Lock-free event broadcasting using `DashMap`.
//!
//! Multiple subscribers receive cloned events without blocking the producer.
//! Disconnected receivers are automatically cleaned up on broadcast.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Opaque subscription identifier.
pub type SubscriptionId = u64;

/// Async event broadcaster backed by `DashMap` + unbounded tokio channels.
pub struct EventBroadcaster<T>
where
    T: Clone + Send + Sync + 'static,
{
    subscribers: DashMap<SubscriptionId, UnboundedSender<T>>,
    next_id: AtomicU64,
    broadcast_count: AtomicU64,
    failed_sends: AtomicU64,
}

impl<T> EventBroadcaster<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Create an empty broadcaster with no subscribers.
    pub fn new() -> Self {
        Self {
            subscribers: DashMap::new(),
            next_id: AtomicU64::new(0),
            broadcast_count: AtomicU64::new(0),
            failed_sends: AtomicU64::new(0),
        }
    }

    /// Subscribe; returns `(id, receiver)`. Use `id` to unsubscribe later.
    pub fn subscribe(&self) -> (SubscriptionId, UnboundedReceiver<T>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::unbounded_channel();
        self.subscribers.insert(id, tx);
        (id, rx)
    }

    /// Unsubscribe. Idempotent.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.subscribers.remove(&id);
    }

    /// Broadcast to all subscribers. Disconnected receivers are pruned.
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

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Total broadcasts sent.
    pub fn broadcast_count(&self) -> u64 {
        self.broadcast_count.load(Ordering::Relaxed)
    }

    /// Total failed sends (disconnected receivers).
    pub fn failed_sends(&self) -> u64 {
        self.failed_sends.load(Ordering::Relaxed)
    }

    /// Drop all subscribers.
    pub fn clear(&self) {
        self.subscribers.clear();
    }

    /// True if any subscribers are registered.
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

/// Synchronous variant using `std::sync::mpsc` channels.
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
    /// Create an empty sync broadcaster.
    pub fn new() -> Self {
        Self {
            subscribers: DashMap::new(),
            next_id: AtomicU64::new(0),
            broadcast_count: AtomicU64::new(0),
            failed_sends: AtomicU64::new(0),
        }
    }

    /// Subscribe; returns `(id, receiver)`.
    pub fn subscribe(&self) -> (SubscriptionId, std::sync::mpsc::Receiver<T>) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = std::sync::mpsc::channel();
        self.subscribers.insert(id, tx);
        (id, rx)
    }

    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.subscribers.remove(&id);
    }

    /// Broadcast to all subscribers. Disconnected receivers are pruned.
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

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Total broadcasts sent.
    pub fn broadcast_count(&self) -> u64 {
        self.broadcast_count.load(Ordering::Relaxed)
    }

    /// Total failed sends.
    pub fn failed_sends(&self) -> u64 {
        self.failed_sends.load(Ordering::Relaxed)
    }

    /// Drop all subscribers.
    pub fn clear(&self) {
        self.subscribers.clear();
    }

    /// True if any subscribers are registered.
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

        drop(rx1);

        broadcaster.broadcast(TestEvent { value: 1 });

        assert_eq!(rx2.recv().await.unwrap().value, 1);
        // Dropped rx1 should have been pruned
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

        for h in handles {
            h.join().unwrap();
        }

        // 5 threads * 100 events = 500 per subscriber
        for (_, rx) in receivers {
            let mut count = 0;
            while rx.try_recv().is_ok() {
                count += 1;
            }
            assert_eq!(count, 500);
        }
    }
}
