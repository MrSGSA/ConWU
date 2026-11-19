use std::{collections::HashSet, net::SocketAddr};

#[derive(Default)]
pub(super) struct CandidateAttempts {
    // Oldest attempt first. Only addresses in the current candidate list are kept.
    attempted: Vec<SocketAddr>,
}

impl CandidateAttempts {
    pub(super) fn order(
        &mut self,
        mut targets: Vec<SocketAddr>,
        last_direct: Option<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut unique = HashSet::new();
        targets.retain(|target| unique.insert(*target));
        self.attempted.retain(|target| unique.contains(target));
        targets.sort_by_key(|target| {
            let attempt = self.attempted.iter().position(|address| address == target);
            (attempt, Some(*target) != last_direct)
        });
        targets
    }

    pub(super) fn record(&mut self, target: SocketAddr) {
        self.attempted.retain(|address| *address != target);
        self.attempted.push(target);
    }

    pub(super) fn clear(&mut self) {
        self.attempted.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn address(port: u16) -> SocketAddr {
        (Ipv4Addr::LOCALHOST, port).into()
    }

    #[test]
    fn reconnect_tries_later_unique_candidates_across_rounds() {
        let mut attempts = CandidateAttempts::default();
        let targets = vec![
            address(1),
            address(1),
            address(2),
            address(3),
            address(4),
            address(5),
            address(5),
        ];
        let first = attempts.order(targets.clone(), None);
        assert_eq!(first, (1..=5).map(address).collect::<Vec<_>>());
        for target in first.into_iter().take(4) {
            attempts.record(target);
        }
        let next = attempts.order(targets.clone(), None);
        assert_eq!(next, [5, 1, 2, 3, 4].map(address));
        for target in next.into_iter().take(4) {
            attempts.record(target);
        }
        assert_eq!(attempts.order(targets, None), [4, 5, 1, 2, 3].map(address));
    }

    #[test]
    fn confirmed_address_gets_first_attempt_only_while_advertised() {
        let mut attempts = CandidateAttempts::default();
        let preferred = Some(address(3));
        let targets = (1..=3).map(address).collect::<Vec<_>>();
        assert_eq!(
            attempts.order(targets.clone(), preferred),
            [3, 1, 2].map(address)
        );
        attempts.record(address(3));
        assert_eq!(
            attempts.order(targets.clone(), preferred),
            [1, 2, 3].map(address)
        );
        assert_eq!(
            attempts.order(vec![address(1), address(2)], preferred),
            [1, 2].map(address)
        );
        assert_eq!(
            attempts.order(targets.clone(), preferred),
            [3, 1, 2].map(address)
        );
        attempts.record(address(3));
        attempts.clear();
        assert_eq!(attempts.order(targets, preferred), [3, 1, 2].map(address));
    }
}
