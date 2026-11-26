use std::{
    cmp::Reverse,
    collections::{BTreeSet, VecDeque},
};

const HISTORY_SIZE: usize = 64;
const SEQUENTIAL_WINDOW: usize = 4;
const MIN_PATTERN_SAMPLES: usize = 3;
const MIN_PBA_PAIRS: usize = 4;
const MIN_RANDOM_SAMPLES: usize = 10;
const MIN_PBA_BLOCK: u16 = 64;
const MAX_PBA_BLOCK: u16 = 256;
const MAX_SEQUENTIAL_SPAN: i32 = 32;
const MIN_STRIDE: u16 = 2;
const MAX_STRIDE: u16 = 512;
const MAX_SMALL_STRIDE: u16 = 7;
const SIGNIFICANCE: f64 = 0.01;
const RESIDUAL_ORDER: [i8; 5] = [0, -1, 1, -2, 2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortDomain {
    min: u16,
    max: u16,
}

impl Default for PortDomain {
    fn default() -> Self {
        Self {
            min: 1024,
            max: u16::MAX,
        }
    }
}

impl PortDomain {
    /// Creates an inclusive dynamic port domain.
    pub fn new(min: u16, max: u16) -> Option<Self> {
        (min <= max).then_some(Self { min, max })
    }

    pub fn contains(self, port: u16) -> bool {
        (self.min..=self.max).contains(&port)
    }

    fn size(self) -> i32 {
        i32::from(self.max) - i32::from(self.min) + 1
    }

    fn crosses_boundary(self, first: u16, last: u16) -> bool {
        let edge_span = (self.size() / 4).min(4 * i32::from(MAX_STRIDE));
        self.contains(first)
            && self.contains(last)
            && self.size() - i32::from(first.abs_diff(last)) <= edge_span
    }

    fn short_arc_diff(self, last: u16, first: u16) -> i32 {
        let delta = i32::from(last) - i32::from(first);
        if self.crosses_boundary(first, last) {
            signed_mod(delta, self.size())
        } else {
            delta
        }
    }

    fn wrap_port(self, port: i64) -> u16 {
        let min = i64::from(self.min);
        (min + (port - min).rem_euclid(i64::from(self.size()))) as u16
    }
}

fn signed_mod(delta: i32, modulus: i32) -> i32 {
    let residue = delta.rem_euclid(modulus);
    if residue >= modulus - modulus / 2 {
        residue - modulus
    } else {
        residue
    }
}

/// Local port coefficient in the mapping model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortCoupling {
    Independent = 0,
    Coupled = 1,
}

impl PortCoupling {
    fn offset(self, from: u16, to: u16) -> i32 {
        self as i32 * (i32::from(to) - i32::from(from))
    }
}

/// One round in send order. Callers can vary `l2 - l1` during warmup to
/// distinguish an independent counter from local port coupling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingObservation {
    pub l1: u16,
    pub l_mid: u16,
    pub l2: u16,
    pub p1: u16,
    /// The trailing mapping may time out.
    pub p2: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatRegime {
    /// Short consistent spans with a unit step.
    Sequential {
        beta: PortCoupling,
    },
    Strided {
        beta: PortCoupling,
        stride: u16,
        residuals: Vec<i8>,
    },
    /// Random allocation within an inferred inclusive port block.
    BoundedRandom {
        min: u16,
        max: u16,
    },
    Random,
}

/// Keep one estimator per mapping path. Recent pairs train the counter models.
/// Port block inference retains the extrema of all observed mapping ports.
pub struct NatPortEstimator {
    full_domain: PortDomain,
    wrap_candidate: Option<PortDomain>,
    domain: PortDomain,
    history: VecDeque<MappingObservation>,
    observed_ports: Option<PortDomain>,
    regime: Option<NatRegime>,
}

impl Default for NatPortEstimator {
    fn default() -> Self {
        let full = PortDomain::default();
        // A 15-bit allocator is one possible wrap domain.
        let compact = PortDomain::new(full.min, i16::MAX as u16);
        Self::new(full, compact)
    }
}

impl NatPortEstimator {
    /// A smaller domain can be inferred from a boundary crossing. Its range
    /// must be a proper subset of the full domain.
    pub fn new(full_domain: PortDomain, wrap_candidate: Option<PortDomain>) -> Self {
        Self {
            full_domain,
            wrap_candidate: wrap_candidate.filter(|inner| {
                full_domain.contains(inner.min)
                    && full_domain.contains(inner.max)
                    && *inner != full_domain
            }),
            domain: full_domain,
            history: VecDeque::new(),
            observed_ports: None,
            regime: None,
        }
    }

    /// Use the current domain when ranking a round.
    pub fn domain(&self) -> PortDomain {
        self.domain
    }

    /// A narrower wrap domain still consistent with all observed anchors.
    pub fn alternate_domain(&self) -> Option<PortDomain> {
        self.wrap_candidate.filter(|&domain| domain != self.domain)
    }

    /// Returns `None` while evidence is insufficient or inconclusive.
    pub fn regime(&self) -> Option<&NatRegime> {
        self.regime.as_ref()
    }

    /// With a missing tail, the first anchor still contributes to port bounds.
    pub fn observe(&mut self, observation: MappingObservation) {
        let previous_domain = self.domain;
        let previous_ports = self.observed_ports;
        for port in [Some(observation.p1), observation.p2].into_iter().flatten() {
            if self.full_domain.contains(port) {
                let bounds = self.observed_ports.unwrap_or(PortDomain {
                    min: port,
                    max: port,
                });
                self.observed_ports = Some(PortDomain {
                    min: bounds.min.min(port),
                    max: bounds.max.max(port),
                });
            }
        }
        if let Some(inner) = self.wrap_candidate {
            if !inner.contains(observation.p1)
                || observation.p2.is_some_and(|p2| !inner.contains(p2))
            {
                self.wrap_candidate = None;
                self.domain = self.full_domain;
            } else if observation
                .p2
                .is_some_and(|p2| inner.crosses_boundary(observation.p1, p2))
            {
                self.domain = inner;
            }
        }

        if self.full_domain.contains(observation.p1)
            && observation
                .p2
                .is_some_and(|p2| self.full_domain.contains(p2))
        {
            if self.history.len() == HISTORY_SIZE {
                self.history.pop_front();
            }
            self.history.push_back(observation);
        } else if self.domain == previous_domain && self.observed_ports == previous_ports {
            return;
        }

        // Keep the original anchors so domain changes re-evaluate earlier pairs.
        let (raw, compensated): (Vec<_>, Vec<_>) = self
            .history
            .iter()
            .filter_map(|pair| {
                let raw = self.domain.short_arc_diff(pair.p2?, pair.p1);
                let local = PortCoupling::Coupled.offset(pair.l1, pair.l2);
                Some((raw, raw - local))
            })
            .unzip();
        self.regime = infer_regime(&raw, &compensated, self.domain, self.observed_ports);
    }
}

fn infer_regime(
    raw: &[i32],
    compensated: &[i32],
    domain: PortDomain,
    observed_ports: Option<PortDomain>,
) -> Option<NatRegime> {
    if raw.len() < MIN_PATTERN_SAMPLES {
        return None;
    }

    let bounded = observed_ports
        .filter(|_| raw.len() >= MIN_PBA_PAIRS)
        .and_then(|observed| infer_port_block(observed).map(|block| (observed, block)));
    let bounded_span = bounded.map(|(observed, _)| observed.size().max(i32::from(MIN_PBA_BLOCK)));
    let raw_seq = sequential_score(raw, bounded_span);
    let comp_seq = sequential_score(compensated, bounded_span);
    let start = raw.len().saturating_sub(SEQUENTIAL_WINDOW);
    let first_gap = raw[start] - compensated[start];
    let varied_gaps = raw[start..]
        .iter()
        .zip(&compensated[start..])
        .any(|(raw, comp)| raw - comp != first_gap);
    let sequential = match (raw_seq, comp_seq) {
        (Some(raw_score), Some(comp_score)) if varied_gaps && comp_score < raw_score => {
            Some(PortCoupling::Coupled)
        }
        (Some(_), _) => Some(PortCoupling::Independent),
        (None, Some(_)) => Some(PortCoupling::Coupled),
        (None, None) => None,
    };

    let hypotheses = [
        (PortCoupling::Independent, raw, raw_seq),
        (PortCoupling::Coupled, compensated, comp_seq),
    ];
    // Bonferroni correction covers both hypotheses and every tested stride.
    let tests = hypotheses.len() as f64 * f64::from(MAX_STRIDE - MIN_STRIDE + 1);
    let cutoff = SIGNIFICANCE / tests;
    let mut best = None;
    let mut best_p = f64::INFINITY;
    let noise_span = bounded_span.map_or(domain.size(), |span| span.min(domain.size()));
    // A short, coherent span can resolve beta before divisibility, since
    // the choice of local gaps can itself introduce a lattice.
    for (beta, deltas, score) in hypotheses {
        if let Some((stride, p)) = best_stride(deltas, noise_span, score.is_some(), cutoff)
            && p < best_p
            && sequential.is_none_or(|preferred| beta == preferred)
        {
            best = Some((beta, stride, deltas));
            best_p = p;
        }
    }
    if let Some((beta, stride, deltas)) = best {
        return Some(NatRegime::Strided {
            beta,
            stride,
            residuals: select_residuals(deltas, stride),
        });
    }

    if let Some(beta) = sequential {
        return Some(NatRegime::Sequential { beta });
    }
    if let Some((_, block)) = bounded {
        return Some(NatRegime::BoundedRandom {
            min: block.min,
            max: block.max,
        });
    }
    (raw.len() >= MIN_RANDOM_SAMPLES).then_some(NatRegime::Random)
}

fn sequential_score(
    deltas: &[i32],
    bounded_span: Option<i32>,
) -> Option<(Reverse<usize>, i32, i32)> {
    let recent = &deltas[deltas.len().saturating_sub(SEQUENTIAL_WINDOW)..];
    let positive = recent.iter().filter(|&&delta| delta > 0).count();
    let negative = recent.iter().filter(|&&delta| delta < 0).count();
    let same_sign = positive.max(negative);
    if same_sign * 4 < recent.len() * 3 {
        return None;
    }

    let mut magnitudes: Vec<_> = recent.iter().map(|delta| delta.abs()).collect();
    magnitudes.sort_unstable();
    let middle = magnitudes.len() / 2;
    let median_twice = magnitudes[(magnitudes.len() - 1) / 2] + magnitudes[middle];
    let spread = magnitudes[magnitudes.len() - 1] - magnitudes[0];
    if median_twice > 2 * MAX_SEQUENTIAL_SPAN
        || bounded_span.is_some_and(|span| !sequential_in_block(deltas, span))
    {
        return None;
    }
    Some((Reverse(same_sign), spread, median_twice))
}

fn sequential_in_block(deltas: &[i32], span: i32) -> bool {
    // A narrow allocator often produces short gaps of the same sign. Require
    // concentration across the training window with room for occasional noise.
    let mut ordered = deltas.to_vec();
    ordered.sort_unstable();
    let samples = ordered.len();
    let support = samples - samples / 8;
    let width = ordered
        .windows(support)
        .map(|gaps| gaps[support - 1] - gaps[0] + 1)
        .min()
        .unwrap();
    let chance = (f64::from(width) / f64::from(span - 1)).min(1.0);
    // Any sample can anchor the interval. Each remaining uniform tail has
    // at most width/(span-1) chance to fall inside it given the first port.
    let p = samples as f64 * binomial_tail(samples - 1, support - 1, chance);
    p <= SIGNIFICANCE / 2.0
}

fn infer_port_block(bounds: PortDomain) -> Option<PortDomain> {
    if bounds.size() > i32::from(MAX_PBA_BLOCK) {
        return None;
    }
    for width in [MIN_PBA_BLOCK, 128, MAX_PBA_BLOCK] {
        let min = (bounds.min / width) * width;
        let max = min + (width - 1);
        if bounds.max <= max {
            return Some(PortDomain { min, max });
        }
    }
    Some(bounds)
}

fn best_stride(
    deltas: &[i32],
    noise_span: i32,
    sequential: bool,
    cutoff: f64,
) -> Option<(u16, f64)> {
    // A zero difference supplies residual information and divides by every stride.
    let informative: Vec<_> = deltas.iter().copied().filter(|&delta| delta != 0).collect();
    if informative.len() < MIN_PATTERN_SAMPLES || noise_span <= 1 {
        return None;
    }
    let small_spans = informative
        .iter()
        .filter(|delta| delta.abs() <= MAX_SEQUENTIAL_SPAN)
        .count();
    let clustered = small_spans * 4 >= informative.len() * 3;
    let mut best = None;
    let mut best_p = f64::INFINITY;
    for stride in MIN_STRIDE..=MAX_STRIDE {
        let small_stride = stride <= MAX_SMALL_STRIDE;
        if small_stride && !clustered {
            continue;
        }

        let step = i32::from(stride);
        let mut hits = 0;
        let mut near = 0;
        let mut first_hit = None;
        let mut varied_hits = false;
        for &delta in &informative {
            let residual = signed_mod(delta, step);
            if residual.abs() <= 2 {
                near += 1;
            }
            if residual == 0 {
                hits += 1;
                varied_hits |= *first_hit.get_or_insert(delta.abs()) != delta.abs();
            }
        }
        // Multiple observed spans distinguish a small lattice from a short,
        // repeating gap in an ordinary sequential allocator.
        if hits == 0
            || near * 4 < informative.len() * 3
            || (small_stride || sequential) && !varied_hits
        {
            continue;
        }

        // Conditional on the first anchor and local gap, uniform port noise
        // spans M consecutive differences. At most ceil(M/s) are divisible.
        // Removing zero leaves at least M-1 possible differences.
        let max_multiples = (noise_span + step - 1) / step;
        let chance = (f64::from(max_multiples) / f64::from(noise_span - 1)).min(1.0);
        let p = binomial_tail(informative.len(), hits, chance);
        if p <= cutoff && p < best_p {
            best = Some((stride, p));
            best_p = p;
        }
    }
    best
}

fn binomial_tail(trials: usize, hits: usize, chance: f64) -> f64 {
    let mut mass = chance.powi(trials as i32);
    let mut tail = mass;
    let odds = (1.0 - chance) / chance;
    for successes in (hits + 1..=trials).rev() {
        mass *= successes as f64 / (trials - successes + 1) as f64 * odds;
        tail += mass;
    }
    tail
}

fn select_residuals(deltas: &[i32], stride: u16) -> Vec<i8> {
    let mut counts = [0; RESIDUAL_ORDER.len()];
    for &delta in deltas {
        let residual = signed_mod(delta, i32::from(stride));
        if (-2..=2).contains(&residual) {
            counts[(residual + 2) as usize] += 1;
        }
    }
    if counts[2] * 100 >= deltas.len() * 85 {
        return vec![0];
    }

    let mut ordered = RESIDUAL_ORDER;
    let count = |residual: i8| counts[(residual + 2) as usize];
    ordered.sort_by_key(|&residual| Reverse(count(residual)));
    let mut selected = Vec::new();
    let mut covered = 0;
    // When outliers make 90% unreachable, keep the observed in-range offsets.
    for residual in ordered
        .into_iter()
        .take_while(|&residual| count(residual) > 0)
    {
        selected.push(residual);
        covered += count(residual);
        if covered * 10 >= deltas.len() * 9 {
            break;
        }
    }
    selected
}

/// Reports a phase mismatch between the two anchors for a strided model.
pub fn has_anchor_phase_shift(
    domain: PortDomain,
    observation: MappingObservation,
    regime: &NatRegime,
) -> bool {
    let NatRegime::Strided { beta, stride, .. } = regime else {
        return false;
    };
    observation.p2.is_some_and(|p2| {
        anchor_gap(domain, observation, *beta, p2) % i32::from((*stride).max(1)) != 0
    })
}

fn anchor_gap(
    domain: PortDomain,
    observation: MappingObservation,
    beta: PortCoupling,
    p2: u16,
) -> i32 {
    domain.short_arc_diff(p2, observation.p1) - beta.offset(observation.l1, observation.l2)
}

/// Count the modeled ports strictly between a short, aligned pair of anchors.
pub fn short_bracket_candidates(
    domain: PortDomain, observation: MappingObservation, regime: &NatRegime,
) -> usize {
    let NatRegime::Strided { residuals, .. } = regime else {
        return 0;
    };
    let Some(steps) = bracket_stride_span(domain, observation, regime) else { return 0 };
    if steps > 12 { return 0; }
    steps.saturating_sub(1) * residuals.len().max(1)
}

pub fn bracket_stride_span(
    domain: PortDomain, observation: MappingObservation, regime: &NatRegime,
) -> Option<usize> {
    let (Some(last), NatRegime::Strided { beta, stride, residuals }) = (observation.p2, regime) else {
        return None;
    };
    let stride = i32::from((*stride).max(1));
    let gap = anchor_gap(domain, observation, *beta, last);
    aligned_steps(gap, stride, residuals).map(|steps| steps.unsigned_abs() as usize)
}

/// The anchors may have different residuals around the same stride lattice.
fn aligned_steps(gap: i32, stride: i32, residuals: &[i8]) -> Option<i32> {
    if gap % stride == 0 {
        return Some(gap / stride);
    }
    let steps = (f64::from(gap) / f64::from(stride)).round() as i32;
    let remainder = gap - steps * stride;
    residuals.iter().any(|&head| residuals.iter().any(|&tail| {
        i32::from(tail) - i32::from(head) == remainder
    })).then_some(steps)
}

#[derive(Clone, Copy, Debug)]
pub struct BurstTiming {
    pub first_us: u64,
    pub middle_us: u64,
    pub last_us: u64,
}

impl BurstTiming {
    pub fn alpha(self) -> Option<f64> {
        let span = self.last_us.checked_sub(self.first_us)?;
        (span != 0).then(|| (i128::from(self.middle_us) - i128::from(self.first_us)) as f64 / span as f64)
    }
}

/// Rank unique public ports for the middle send. Unbounded random yields an
/// empty list so the caller can immediately select its fallback transport.
pub fn rank_candidates(
    domain: PortDomain,
    observation: MappingObservation,
    regime: &NatRegime,
    max_candidates: usize,
) -> Vec<u16> {
    rank_candidates_with_timing(domain, observation, regime, max_candidates, None)
}

pub fn rank_candidates_with_timing(
    domain: PortDomain,
    observation: MappingObservation,
    regime: &NatRegime,
    max_candidates: usize,
    timing: Option<BurstTiming>,
) -> Vec<u16> {
    if max_candidates == 0 {
        return Vec::new();
    }
    let (beta, stride, residuals) = match regime {
        NatRegime::Sequential { beta } => (*beta, 1, &[0][..]),
        NatRegime::Strided {
            beta,
            stride,
            residuals,
        } => (*beta, (*stride).max(1), residuals.as_slice()),
        NatRegime::BoundedRandom { min, max } => {
            return rank_block_candidates(
                domain.min.max(*min),
                domain.max.min(*max),
                observation,
                max_candidates,
            );
        }
        NatRegime::Random => return Vec::new(),
    };
    let residuals = if residuals.is_empty() {
        &[0]
    } else {
        residuals
    };
    let stride = i32::from(stride);
    let period = domain.size() / gcd(domain.size(), stride);
    let first_base =
        i64::from(observation.p1) + i64::from(beta.offset(observation.l1, observation.l_mid));
    let last_base = observation
        .p2
        .map(|p2| i64::from(p2) + i64::from(beta.offset(observation.l2, observation.l_mid)));
    let k2 = observation.p2.and_then(|p2| {
        let delta = anchor_gap(domain, observation, beta, p2);
        aligned_steps(delta, stride, residuals)
    });
    // When the anchors give away the phase of the first residual, put the
    // lattice back on its base so its residual list includes both phases.
    let first_base = if let (Some(k), Some(p2)) = (k2, observation.p2) {
        let difference = anchor_gap(domain, observation, beta, p2) - k * stride;
        if difference != 0 {
            let mut phases = residuals.iter().filter(|&&head| {
                residuals.iter().any(|&tail| i32::from(tail) - i32::from(head) == difference)
            });
            match (phases.next(), phases.next()) {
                (Some(&phase), None) => first_base - i64::from(phase),
                _ => first_base,
            }
        } else { first_base }
    } else { first_base };

    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(k2) = k2 {
        seen.insert(domain.wrap_port(first_base));
        seen.insert(domain.wrap_port(first_base + i64::from(k2) * i64::from(stride)));
    }
    let mut push = |base, k: i32, residual: i8| {
        let port = domain.wrap_port(base + i64::from(k) * i64::from(stride) + i64::from(residual));
        if seen.insert(port) {
            candidates.push(port);
        }
        candidates.len() == max_candidates
    };

    if let Some(k2) = k2 {
        let measured = timing.and_then(BurstTiming::alpha);
        let alpha = measured.unwrap_or(0.5).clamp(0.0, 1.0);
        let expected = f64::from(k2) * alpha;
        let lower_mid = expected.floor() as i32;
        let last_tick = k2.rem_euclid(period);
        if let Some(alpha) = measured.filter(|&a| !(0.0..=1.0).contains(&a)) {
            let sign = if k2 < 0 { -1 } else { 1 };
            let k = if alpha < 0.0 { -sign } else { k2 + sign };
            // A bounded wait for the helper can put the tail on the wire
            // first. Keep the nearest point beyond the measured bracket.
            for &residual in residuals {
                if push(first_base, k, residual) { return candidates; }
            }
        }
        if timing.is_some() && k2.unsigned_abs() > 1 {
            let sign = k2.signum();
            let first = sign;
            let last = k2 - sign;
            let nearest = (expected.round() as i32).clamp(first.min(last), first.max(last));
            let mut priority = [first, last, nearest];
            priority.sort_by(|a, b| (f64::from(*a) - expected).abs().total_cmp(&(f64::from(*b) - expected).abs()));
            for k in priority {
                for &residual in residuals {
                    if push(first_base, k, residual) {
                        return candidates;
                    }
                }
            }
        }
        // This visits consecutive ticks in midpoint-distance order. One
        // period covers the lattice, including both occupied tick classes.
        for index in 0..period {
            let distance = index / 2;
            let k = if index % 2 == 0 {
                lower_mid - distance
            } else {
                lower_mid + 1 + distance
            };
            let tick = k.rem_euclid(period);
            if tick == 0 || tick == last_tick {
                continue;
            }
            for &residual in residuals {
                if push(first_base, k, residual) {
                    return candidates;
                }
            }
        }
    } else {
        for distance in 1..=period {
            let mut points = [
                Some((first_base, distance)),
                last_base.map(|base| (base, -distance)),
                Some((first_base, -distance)),
                last_base.map(|base| (base, distance)),
            ];
            if timing.and_then(BurstTiming::alpha).is_some_and(|alpha| alpha > 0.5) && last_base.is_some() {
                points.swap(0, 1);
                points.swap(2, 3);
            }
            for &residual in residuals {
                for (base, k) in points.into_iter().flatten() {
                    if push(base, k, residual) {
                        return candidates;
                    }
                }
            }
        }
    }
    candidates
}

fn rank_block_candidates(
    min: u16,
    max: u16,
    observation: MappingObservation,
    max_candidates: usize,
) -> Vec<u16> {
    let Some(block) = PortDomain::new(min, max) else {
        return Vec::new();
    };
    let width = block.size();
    let anchors = (u32::from(observation.p1) << 16) | u32::from(observation.p2.unwrap_or(0));
    let mixed = anchors.wrapping_mul(0x9e37_79b9);
    let mut offset = ((mixed ^ (mixed >> 16)) % width as u32) as i32;
    let mut step = (3 * width / 8).max(1);
    while gcd(step, width) != 1 {
        step += 1;
    }

    // A coprime step walks the whole block exactly once from the anchor seed.
    let mut candidates = Vec::with_capacity(max_candidates.min(width as usize));
    for _ in 0..width {
        let port = (i32::from(min) + offset) as u16;
        if port != observation.p1 && Some(port) != observation.p2 {
            candidates.push(port);
            if candidates.len() == max_candidates {
                break;
            }
        }
        offset = (offset + step) % width;
    }
    candidates
}

fn gcd(mut a: i32, mut b: i32) -> i32 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

#[cfg(test)]
mod tests;
