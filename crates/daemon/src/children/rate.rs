//! A token bucket for the lines a child prints: bursts up to one second's worth pass, the
//! rest is dropped and counted, so a chatty child cannot flood the daemon's log.

use tokio::time::Instant;

pub enum Take {
    /// Log the line; `dropped` lines before it were not.
    Pass {
        dropped: u64,
    },
    Drop,
}

pub struct RateLimiter {
    per_sec: f64,
    tokens: f64,
    last: Instant,
    dropped: u64,
}

impl RateLimiter {
    pub fn new(per_sec: u32, now: Instant) -> Self {
        let per_sec = f64::from(per_sec.max(1));
        Self {
            per_sec,
            tokens: per_sec,
            last: now,
            dropped: 0,
        }
    }

    pub fn take(&mut self, now: Instant) -> Take {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_sec).min(self.per_sec);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Take::Pass {
                dropped: std::mem::take(&mut self.dropped),
            }
        } else {
            self.dropped += 1;
            Take::Drop
        }
    }

    /// The count of dropped lines not yet reported, and reset it.
    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_burst_passes_up_to_the_rate_then_drops_and_recovers() {
        let t0 = Instant::now();
        let mut l = RateLimiter::new(20, t0);
        let passed = (0..50)
            .filter(|_| matches!(l.take(t0), Take::Pass { .. }))
            .count();
        assert_eq!(passed, 20);
        // Half a second later ten more fit, and the first reports the 30 drops.
        let t1 = t0 + Duration::from_millis(500);
        match l.take(t1) {
            Take::Pass { dropped } => assert_eq!(dropped, 30),
            Take::Drop => panic!("tokens had refilled"),
        }
        let more = (0..20)
            .filter(|_| matches!(l.take(t1), Take::Pass { .. }))
            .count();
        assert_eq!(more, 9);
        assert_eq!(l.take_dropped(), 11);
        assert_eq!(l.take_dropped(), 0);
    }
}
