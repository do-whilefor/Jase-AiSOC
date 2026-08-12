use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct AiReviewBudget {
    max_ratio: f64,
    observed_requests: AtomicU64,
    selected_requests: AtomicU64,
}

impl AiReviewBudget {
    pub fn new(max_ratio: f64) -> Self {
        Self {
            max_ratio: max_ratio.clamp(0.0, 1.0),
            observed_requests: AtomicU64::new(0),
            selected_requests: AtomicU64::new(0),
        }
    }

    pub fn observe_and_select(&self, eligible: bool) -> bool {
        let observed = self.observed_requests.fetch_add(1, Ordering::Relaxed) + 1;
        if !eligible || self.max_ratio <= 0.0 {
            return false;
        }

        let allowance = ((observed as f64) * self.max_ratio).floor() as u64;
        if allowance == 0 {
            return false;
        }

        let mut selected = self.selected_requests.load(Ordering::Relaxed);
        loop {
            if selected >= allowance {
                return false;
            }
            match self.selected_requests.compare_exchange_weak(
                selected,
                selected + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => selected = actual,
            }
        }
    }

    pub fn counters(&self) -> (u64, u64) {
        (
            self.observed_requests.load(Ordering::Relaxed),
            self.selected_requests.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_ratio_never_selects() {
        let budget = AiReviewBudget::new(0.0);
        assert!(!budget.observe_and_select(true));
        assert_eq!(budget.counters(), (1, 0));
    }

    #[test]
    fn ratio_is_enforced_across_all_observed_requests() {
        let budget = AiReviewBudget::new(0.25);
        for _ in 0..3 {
            assert!(!budget.observe_and_select(true));
        }
        assert!(budget.observe_and_select(true));
        for _ in 0..4 {
            let _ = budget.observe_and_select(true);
        }
        let (observed, selected) = budget.counters();
        assert_eq!(observed, 8);
        assert_eq!(selected, 2);
        assert!((selected as f64) / (observed as f64) <= 0.25);
    }

    #[test]
    fn ineligible_requests_still_count_toward_global_budget() {
        let budget = AiReviewBudget::new(0.5);
        assert!(!budget.observe_and_select(false));
        assert!(budget.observe_and_select(true));
        assert_eq!(budget.counters(), (2, 1));
    }
}
