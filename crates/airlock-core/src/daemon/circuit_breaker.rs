use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct CircuitBreaker {
    failures: Mutex<Vec<Instant>>,
    window: Duration,
    threshold: usize,
}

impl CircuitBreaker {
    pub fn new(threshold: usize, window: Duration) -> Self {
        Self {
            failures: Mutex::new(Vec::new()),
            window,
            threshold,
        }
    }

    pub fn default_rate_limiter() -> Self {
        Self::new(3, Duration::from_secs(60))
    }

    /// Records a rate-limit error or upstream API failure.
    pub fn record_failure(&self) {
        let now = Instant::now();
        if let Ok(mut lock) = self.failures.lock() {
            lock.push(now);
            // Prune expired failures outside the sliding window
            let cutoff = now.checked_sub(self.window).unwrap_or(now);
            lock.retain(|&t| t >= cutoff);
        }
    }

    /// Checks if the circuit breaker is currently open (tripped).
    pub fn is_open(&self) -> bool {
        let now = Instant::now();
        if let Ok(mut lock) = self.failures.lock() {
            let cutoff = now.checked_sub(self.window).unwrap_or(now);
            lock.retain(|&t| t >= cutoff);
            lock.len() >= self.threshold
        } else {
            false
        }
    }

    /// Resets the circuit breaker state.
    pub fn reset(&self) {
        if let Ok(mut lock) = self.failures.lock() {
            lock.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_tripping() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        assert!(!cb.is_open());

        cb.record_failure();
        assert!(!cb.is_open());

        cb.record_failure();
        assert!(!cb.is_open());

        cb.record_failure();
        assert!(cb.is_open(), "Circuit breaker must trip after 3 failures");

        cb.reset();
        assert!(!cb.is_open(), "Circuit breaker must close after reset");
    }
}
