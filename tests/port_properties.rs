use proptest::prelude::*;
use security_assessment_coverage_reporter::parse_ports;

proptest! {
    #[test]
    fn normalized_intervals_preserve_membership(raw in prop::collection::vec((1u16..1000, 1u16..1000), 1..30)) {
        let intervals: Vec<(u16,u16)> = raw.into_iter().map(|(a,b)| (a.min(b),a.max(b))).collect();
        let spec = intervals.iter().map(|(a,b)| format!("{a}-{b}")).collect::<Vec<_>>().join(",");
        let normalized = parse_ports(&spec).unwrap();
        for adjacent in normalized.windows(2) { prop_assert!((adjacent[0].1 as u32) + 1 < adjacent[1].0 as u32); }
        for port in 1u16..1000 { prop_assert_eq!(intervals.iter().any(|(a,b)| *a <= port && port <= *b), normalized.iter().any(|(a,b)| *a <= port && port <= *b)); }
    }
}
