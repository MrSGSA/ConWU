use super::*;
use rand::{SeedableRng, rngs::StdRng, seq::index::sample};

const ROUND: MappingObservation = MappingObservation {
    l1: 52731,
    l_mid: 52737,
    l2: 52738,
    p1: 25468,
    p2: None,
};

fn paired(gap: u16, p1: u16, mapped_delta: i32) -> MappingObservation {
    let p2 = PortDomain::default().wrap_port(i64::from(p1) + i64::from(mapped_delta));
    MappingObservation {
        l2: ROUND.l1 + gap,
        p1,
        p2: Some(p2),
        ..ROUND
    }
}

fn coupled_stride() -> NatRegime {
    NatRegime::Strided {
        beta: PortCoupling::Coupled,
        stride: 129,
        residuals: vec![0],
    }
}

#[test]
fn a_one_port_residual_difference_keeps_the_wide_bracket_center_and_edges() {
    let domain = PortDomain::default();
    let regime = NatRegime::Strided { beta: PortCoupling::Coupled, stride: 129, residuals: vec![0, 1] };
    let timing = BurstTiming { first_us: 0, middle_us: 615, last_us: 1042 };
    for (p1, p2) in [(4223, 6032), (4224, 6031)] {
        let observation = MappingObservation {
            l1: 44680, l_mid: 44681, l2: 44682, p1, p2: Some(p2),
        };
        assert_eq!(bracket_stride_span(domain, observation, &regime), Some(14));
        let ranked = rank_candidates_with_timing(domain, observation, &regime, 6, Some(timing));
        assert_eq!(&ranked[..2], &[5256, 5257]);
        for port in [4353, 4354, 5901, 5902] {
            assert!(ranked.contains(&port), "{port} missing in {ranked:?}");
        }
    }
}

#[test]
fn measured_middle_send_changes_the_first_ranked_port() {
    let anchors = MappingObservation {
        l1: 44678, l_mid: 44680, l2: 44683, p1: 12000, p2: Some(14585),
    };
    let domain = PortDomain::default();
    let regime = coupled_stride();
    let timing = |middle_us| BurstTiming { first_us: 1000, middle_us, last_us: 2000 };
    for (middle, expected) in [(1100, 12260), (1500, 13292), (1900, 14324)] {
        assert_eq!(rank_candidates_with_timing(domain, anchors, &regime, 1, Some(timing(middle))), [expected]);
    }
    assert_eq!(rank_candidates_with_timing(domain, anchors, &regime, 1, Some(timing(2100))), [14711]);
    assert_eq!(rank_candidates_with_timing(domain, anchors, &regime, 1, Some(timing(900))), [11873]);
}

#[test]
fn wide_raw_brackets_reserve_both_edges_and_residuals() {
    let domain = PortDomain::default();
    let regime = NatRegime::Strided { beta: PortCoupling::Coupled, stride: 129, residuals: vec![0, 1] };
    let timing = Some(BurstTiming { first_us: 1000, middle_us: 1500, last_us: 2000 });
    for steps in [13, 30, 49, 50, 60] {
        let p1 = 12000;
        let p2 = p1 + steps * 129 + 5;
        let observation = MappingObservation { l1: 44678, l_mid: 44680, l2: 44683, p1, p2: Some(p2) };
        let ranked = rank_candidates_with_timing(domain, observation, &regime, 8, timing);
        assert_eq!(bracket_stride_span(domain, observation, &regime), Some(usize::from(steps)));
        for mandatory in [p1 + 129 + 2, p1 + 129 + 3, p2 - 129 - 3, p2 - 129 - 2] {
            assert!(ranked[..6].contains(&mandatory), "stride span {steps} is missing {mandatory}: {ranked:?}");
        }
    }
}

#[test]
fn sequential_uses_the_public_gap_with_nonconsecutive_local_ports() {
    let mut estimator = NatPortEstimator::default();
    let expected = NatRegime::Sequential {
        beta: PortCoupling::Independent,
    };
    for (index, gap) in [1, 17, 23, 7].into_iter().cycle().take(64).enumerate() {
        estimator.observe(paired(gap, 45000, 2));
        if index >= 2 {
            assert_eq!(estimator.regime(), Some(&expected));
        }
    }

    let observation = MappingObservation {
        p1: 45000,
        p2: Some(45002),
        ..ROUND
    };
    assert_eq!(
        rank_candidates(
            estimator.domain(),
            observation,
            estimator.regime().unwrap(),
            1
        ),
        [45001]
    );
}

#[test]
fn varied_small_spans_identify_two_and_four_port_steps() {
    for stride in [2, 4] {
        let mut estimator = NatPortEstimator::default();
        for (index, gap) in [1, 17, 23].into_iter().cycle().take(24).enumerate() {
            let ticks = 2 + (index % 4) as i32;
            estimator.observe(paired(gap, 45000, i32::from(stride) * ticks));
        }
        assert_eq!(
            estimator.regime(),
            Some(&NatRegime::Strided {
                beta: PortCoupling::Independent,
                stride,
                residuals: vec![0],
            })
        );
    }
}

#[test]
fn stride_significance_accounts_for_both_coupling_hypotheses() {
    let mut estimator = NatPortEstimator::default();
    for (gap, delta) in [(1, 40), (17, 80), (23, 120)] {
        estimator.observe(paired(gap, 45000, delta));
    }
    assert_eq!(estimator.regime(), None);

    estimator.observe(paired(7, 45000, 160));
    assert_eq!(
        estimator.regime(),
        Some(&NatRegime::Strided {
            beta: PortCoupling::Independent,
            stride: 40,
            residuals: vec![0],
        })
    );
}

#[test]
fn coupled_stride_uses_varied_local_gaps_and_excludes_both_anchors() {
    let mut estimator = NatPortEstimator::default();
    for (gap, ticks) in [
        (1, 2),
        (17, 3),
        (23, 4),
        (5, 5),
        (1, 6),
        (17, 7),
        (23, 8),
        (7, 9),
    ] {
        estimator.observe(paired(gap, 45000, i32::from(gap) + 129 * ticks));
    }
    assert_eq!(estimator.regime(), Some(&coupled_stride()));

    for (ticks, inside, last_anchor) in [(3, [45135, 45264], 45393), (-3, [44748, 44877], 44619)] {
        let observation = paired(7, 45000, 7 + 129 * ticks);
        let candidates = rank_candidates(
            estimator.domain(),
            observation,
            estimator.regime().unwrap(),
            8,
        );
        assert_eq!(candidates[..2], inside);
        assert_eq!(candidates.len(), 8);
        assert!(!candidates.contains(&45006));
        assert!(!candidates.contains(&last_anchor));
    }
}

#[test]
fn residual_learning_uses_the_smallest_high_coverage_set() {
    let mut estimator = NatPortEstimator::default();
    for (index, residual) in [0, 0, -1, 0, 0, 2, 0, -1, 0, 0].into_iter().enumerate() {
        let gap = [1, 17, 23][index % 3];
        let delta = i32::from(gap) + 129 * (index as i32 + 2) + residual;
        estimator.observe(paired(gap, 47100, delta));
    }
    assert_eq!(
        estimator.regime(),
        Some(&NatRegime::Strided {
            beta: PortCoupling::Coupled,
            stride: 129,
            residuals: vec![0, -1],
        })
    );
}

#[test]
fn phase_shift_interleaves_the_compensated_anchor_lattices() {
    let observation = MappingObservation {
        p2: Some(25476),
        ..ROUND
    };
    assert_eq!(
        rank_candidates(PortDomain::default(), observation, &coupled_stride(), 6),
        [25603, 25346, 25345, 25604, 25732, 25217]
    );
}

#[test]
fn missing_tail_keeps_the_learned_model_and_ranks_both_directions() {
    let mut estimator = NatPortEstimator::default();
    for (gap, ticks) in [(1, 2), (17, 3), (23, 4)] {
        estimator.observe(paired(gap, 45000, i32::from(gap) + 129 * ticks));
    }
    estimator.observe(ROUND);
    assert_eq!(estimator.regime(), Some(&coupled_stride()));
    assert_eq!(
        rank_candidates(estimator.domain(), ROUND, estimator.regime().unwrap(), 2),
        [25603, 25345]
    );
}

#[test]
fn uniform_port_noise_abandons_prediction_after_ten_pairs() {
    let mut estimator = NatPortEstimator::default();
    let samples = [
        (33539, 23750),
        (61476, 13976),
        (11623, 20791),
        (46187, 18950),
        (26862, 46230),
        (59935, 13515),
        (22615, 31965),
        (1714, 28465),
        (19569, 37941),
        (27600, 12658),
    ];
    for (index, (p1, p2)) in samples.into_iter().enumerate() {
        let observation = paired([1, 17, 23][index % 3], p1, i32::from(p2) - i32::from(p1));
        estimator.observe(observation);
        if index + 1 < samples.len() {
            assert_eq!(estimator.regime(), None);
        } else {
            assert_eq!(estimator.regime(), Some(&NatRegime::Random));
            assert!(
                rank_candidates(
                    estimator.domain(),
                    observation,
                    estimator.regime().unwrap(),
                    8
                )
                .is_empty()
            );
        }
    }
}

#[test]
fn compact_domain_requires_a_crossing_and_stays_compatible_with_history() {
    let mut estimator = NatPortEstimator::default();
    let full = PortDomain::default();
    let compact = PortDomain::new(1024, 32767).unwrap();
    for gap in [1, 17, 23] {
        estimator.observe(paired(gap, 32500, 2));
    }
    assert_eq!(estimator.domain(), full);

    let crossing = MappingObservation {
        p1: 32767,
        p2: Some(1025),
        ..ROUND
    };
    estimator.observe(crossing);
    assert_eq!(estimator.domain(), compact);
    assert_eq!(
        rank_candidates(estimator.domain(), crossing, estimator.regime().unwrap(), 1),
        [1024]
    );

    estimator.observe(MappingObservation { p1: 45000, ..ROUND });
    assert_eq!(estimator.domain(), full);
    estimator.observe(crossing);
    assert_eq!(estimator.domain(), full);
}

#[test]
fn full_domain_uses_linear_differences_and_wraps_its_own_boundary() {
    let domain = PortDomain::default();
    assert_eq!(domain.short_arc_diff(50000, 11000), 39000);
    assert_eq!(domain.short_arc_diff(1025, 65535), 2);
    assert_eq!(domain.short_arc_diff(65535, 1025), -2);
    let observation = MappingObservation {
        p1: 65535,
        p2: Some(1025),
        ..ROUND
    };
    let regime = NatRegime::Sequential {
        beta: PortCoupling::Independent,
    };
    let candidates = rank_candidates(domain, observation, &regime, 4);
    assert_eq!(candidates[0], 1024);
    assert!(!candidates.contains(&65535));
    assert!(!candidates.contains(&1025));
    assert!(candidates.iter().all(|&port| domain.contains(port)));
}

#[test]
fn short_port_cycles_terminate_and_deduplicate_wrapped_candidates() {
    let domain = PortDomain::new(1024, 1033).unwrap();
    let regime = NatRegime::Strided {
        beta: PortCoupling::Independent,
        stride: 4,
        residuals: vec![0],
    };
    let single = MappingObservation { p1: 1024, ..ROUND };
    assert_eq!(
        rank_candidates(domain, single, &regime, usize::MAX),
        [1028, 1030, 1032, 1026, 1024]
    );
    assert!(rank_candidates(domain, single, &regime, 0).is_empty());

    let with_tail = MappingObservation {
        p2: Some(1028),
        ..single
    };
    assert_eq!(
        rank_candidates(domain, with_tail, &regime, usize::MAX),
        [1030, 1032, 1026]
    );
}

fn pba_round(rng: &mut StdRng, min: u16, max: u16, round: usize) -> (MappingObservation, u16) {
    // Allocate the first anchor, peer mapping, and last anchor uniformly from
    // the free ports of the block, with no reuse within a round.
    let indices = sample(rng, usize::from(max - min) + 1, 3);
    let [p1, target, p2] = std::array::from_fn(|index| min + indices.index(index) as u16);
    let observation = paired([1, 17, 23][round % 3], p1, i32::from(p2) - i32::from(p1));
    (observation, target)
}

#[test]
fn six_rounds_find_the_smallest_aligned_pba_block() {
    let (min, max) = (20480, 20543);
    let mut rng = StdRng::seed_from_u64(64);
    let mut estimator = NatPortEstimator::default();
    let mut observation = ROUND;
    for round in 0..6 {
        (observation, _) = pba_round(&mut rng, min, max, round);
        estimator.observe(observation);
        if round < 3 {
            assert!(!matches!(
                estimator.regime(),
                Some(NatRegime::BoundedRandom { .. })
            ));
        }
    }
    assert_eq!(
        estimator.regime(),
        Some(&NatRegime::BoundedRandom { min, max })
    );

    let rank = |observation, limit| {
        rank_candidates(
            estimator.domain(),
            observation,
            estimator.regime().unwrap(),
            limit,
        )
    };
    let candidates = rank(observation, 16);
    assert_eq!(candidates.len(), 16);
    assert_eq!(candidates, rank(observation, 16));
    assert!(rank(observation, 0).is_empty());
    let available: BTreeSet<_> = (min..=max)
        .filter(|&port| port != observation.p1 && Some(port) != observation.p2)
        .collect();
    let all = rank(observation, usize::MAX);
    assert_eq!(all.len(), available.len());
    assert_eq!(all.into_iter().collect::<BTreeSet<_>>(), available);
    assert!(candidates.iter().all(|port| available.contains(port)));

    observation.p2 = None;
    let single = rank(observation, usize::MAX);
    assert_eq!(single.len(), 63);
    assert!(!single.contains(&observation.p1));
}

#[test]
fn pba_128_port_block_hits_at_least_one_in_ten_rounds() {
    let (min, max) = (30080, 30207);
    let expected = NatRegime::BoundedRandom { min, max };
    let mut rng = StdRng::seed_from_u64(128);
    let mut estimator = NatPortEstimator::default();
    for round in 0..6 {
        estimator.observe(pba_round(&mut rng, min, max, round).0);
    }
    assert_eq!(estimator.regime(), Some(&expected));

    let mut hits = 0;
    let mut first_choices = BTreeSet::new();
    for round in 6..206 {
        let (observation, target) = pba_round(&mut rng, min, max, round);
        estimator.observe(observation);
        assert_eq!(estimator.regime(), Some(&expected), "round {round}");
        let candidates = rank_candidates(
            estimator.domain(),
            observation,
            estimator.regime().unwrap(),
            16,
        );
        assert_eq!(candidates.len(), 16);
        first_choices.insert(candidates[0]);
        hits += usize::from(candidates.contains(&target));
    }
    println!("PBA 128-port block yielded {hits}/200 hits with 16 candidates");
    assert!(hits >= 20, "{hits}/200 hits with 16 candidates");
    assert!(first_choices.len() > 64);
}

#[test]
fn non_aligned_pba_uses_a_larger_block_or_the_observed_range() {
    for (min, max, expected_block) in [(20569, 20667, Some((20480, 20735))), (20694, 20793, None)] {
        let mut rng = StdRng::seed_from_u64(u64::from(min));
        let mut estimator = NatPortEstimator::default();
        let mut observed_min = max;
        let mut observed_max = min;
        let mut observation = ROUND;
        for round in 0..8 {
            (observation, _) = pba_round(&mut rng, min, max, round);
            for port in [observation.p1, observation.p2.unwrap()] {
                observed_min = observed_min.min(port);
                observed_max = observed_max.max(port);
            }
            estimator.observe(observation);
        }
        assert!(observed_max - observed_min < 120);
        assert_ne!(observed_min / 64, observed_max / 64);
        let (min, max) = expected_block.unwrap_or((observed_min, observed_max));
        assert_eq!(
            estimator.regime(),
            Some(&NatRegime::BoundedRandom { min, max })
        );
        let candidates = rank_candidates(
            estimator.domain(),
            observation,
            estimator.regime().unwrap(),
            usize::MAX,
        );
        assert_eq!(candidates.len(), usize::from(max - min) - 1);
        assert_eq!(
            candidates.into_iter().collect::<BTreeSet<_>>(),
            (min..=max)
                .filter(|&port| port != observation.p1 && Some(port) != observation.p2)
                .collect(),
        );
    }
}

#[test]
fn historic_ports_outside_the_block_remain_evidence_after_window_rollover() {
    let mut estimator = NatPortEstimator::default();
    let deltas = [49, -43, 37, -41, 53, -47, 59, -31];
    let rounds = deltas.into_iter().cycle().map(|delta| {
        let p1 = if delta > 0 { 20480 } else { 20543 };
        paired(1, p1, delta)
    });
    for observation in rounds.clone().take(MIN_RANDOM_SAMPLES) {
        estimator.observe(observation);
    }
    assert_eq!(
        estimator.regime(),
        Some(&NatRegime::BoundedRandom {
            min: 20480,
            max: 20543
        })
    );

    estimator.observe(MappingObservation { p1: 20736, ..ROUND });
    assert_eq!(estimator.regime(), Some(&NatRegime::Random));
    for observation in rounds.take(HISTORY_SIZE + 1) {
        estimator.observe(observation);
    }
    assert_eq!(estimator.regime(), Some(&NatRegime::Random));
}

#[test]
fn pba_block_ranking_handles_the_domain_boundary() {
    assert_eq!(
        infer_port_block(PortDomain::new(65280, 65535).unwrap()),
        PortDomain::new(65280, 65535)
    );
    let domain = PortDomain::new(65528, 65535).unwrap();
    let regime = NatRegime::BoundedRandom {
        min: 65280,
        max: 65535,
    };
    let observation = MappingObservation {
        p1: 65531,
        p2: Some(65531),
        ..ROUND
    };
    let all = rank_candidates(domain, observation, &regime, usize::MAX);
    assert_eq!(all.len(), 7);
    assert_eq!(
        all.into_iter().collect::<BTreeSet<_>>(),
        (65528..=65535).filter(|&port| port != 65531).collect()
    );
}
