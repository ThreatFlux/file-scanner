use super::*;

#[test]
fn preserves_legacy_entry_fields_and_context_offsets() {
    let tracker = StringTracker::new();
    tracker
        .track_string(
            "tracked value",
            "/fixture/input.txt",
            "fixture-hash",
            "fixture-tool",
            StringContext::FileString { offset: Some(7) },
        )
        .unwrap();
    let entry = tracker.get_string_details("tracked value").unwrap();
    assert_eq!(entry.total_occurrences, 1);
    assert_eq!(
        entry.unique_files,
        HashSet::from(["/fixture/input.txt".into()])
    );
    assert!(matches!(
        entry.occurrences[0].context,
        StringContext::FileString { offset: Some(7) }
    ));
    let json = serde_json::to_value(entry).unwrap();
    assert_eq!(
        json["unique_files"],
        serde_json::json!(["/fixture/input.txt"])
    );
    assert_eq!(json["occurrences"][0]["context"]["FileString"]["offset"], 7);
    assert!(json.get("unique_file_identities").is_none());
    assert!(json.get("suspicious_indicators").is_none());
}

#[test]
fn keeps_distinct_paths_with_identical_content_hashes() {
    let tracker = StringTracker::new();
    for path in ["/fixture/a.txt", "/fixture/b.txt"] {
        tracker
            .track_string(
                "same value",
                path,
                "identical-hash",
                "fixture-tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }
    let entry = tracker.get_string_details("same value").unwrap();
    assert_eq!(
        entry.unique_files,
        HashSet::from(["/fixture/a.txt".into(), "/fixture/b.txt".into()])
    );
    assert_eq!(tracker.get_statistics(None).total_files_analyzed, 2);
}

#[test]
fn counts_changed_content_as_distinct_file_identities() {
    let tracker = StringTracker::new();
    for hash in ["first-version", "second-version"] {
        tracker
            .track_string(
                "same value",
                "/fixture/a.txt",
                hash,
                "fixture-tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }
    let entry = tracker.get_string_details("same value").unwrap();
    assert_eq!(entry.unique_files, HashSet::from(["/fixture/a.txt".into()]));
    assert_eq!(tracker.get_statistics(None).total_files_analyzed, 2);
}

#[test]
fn preserves_legacy_entropy_samples_and_length_bucket_keys() {
    let tracker = StringTracker::new();
    for value in ["abcdefghijklmnopqrs".into(), "a".repeat(201)] {
        tracker
            .track_string(
                &value,
                "/fixture/a.txt",
                "fixture-hash",
                "fixture-tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.length_distribution.get("200+"), Some(&1));
    assert!(!stats.length_distribution.contains_key("201+"));
    assert_eq!(stats.high_entropy_strings.len(), 1);
    assert_eq!(stats.high_entropy_strings[0].0, "abcdefghijklmnopqrs");
    assert!(stats.high_entropy_strings[0].1 > 4.0);
    assert!(stats.high_entropy_strings[0].1 < 4.5);
    assert!(
        !tracker
            .get_string_details("abcdefghijklmnopqrs")
            .unwrap()
            .is_suspicious
    );
}

#[test]
fn continues_indexing_valid_values_after_an_oversized_extraction() {
    let tracker = StringTracker::new();
    let oversized = "x".repeat(tracker.inner.config().max_input_bytes + 1);
    assert!(tracker
        .track_strings_from_results(
            &[oversized.clone(), "malware_token".into()],
            "/fixture/a.txt",
            "fixture-hash",
            "fixture-tool"
        )
        .is_err());
    assert!(tracker.get_string_details(&oversized).is_none());
    assert!(tracker.get_string_details("malware_token").is_some());
    assert_eq!(tracker.get_statistics(None).total_unique_strings, 1);
}

#[test]
fn rejects_invalid_filters_without_disclosing_unfiltered_statistics() {
    let tracker = StringTracker::new();
    tracker
        .track_string(
            "one value",
            "/fixture/input.txt",
            "fixture-hash",
            "fixture-tool",
            StringContext::FileString { offset: None },
        )
        .unwrap();
    for filter in [
        StringFilter {
            regex_pattern: Some("[".into()),
            ..StringFilter::default()
        },
        StringFilter {
            min_occurrences: Some(2),
            max_occurrences: Some(1),
            ..StringFilter::default()
        },
    ] {
        assert!(tracker.try_get_statistics(Some(&filter)).is_err());
        assert_eq!(
            tracker.get_statistics(Some(&filter)).total_unique_strings,
            0
        );
    }
    assert_eq!(tracker.get_statistics(None).total_unique_strings, 1);
}

#[test]
fn validates_query_bounds_and_preserves_legacy_count_width() {
    let tracker = StringTracker::new();
    let oversized = "x".repeat(tracker.inner.config().max_input_bytes + 1);
    assert!(tracker.try_search_strings(&oversized, 10).is_err());
    assert!(tracker.try_get_related_strings(&oversized, 10).is_err());
    assert!(tracker.search_strings(&oversized, 10).is_empty());
    assert!(tracker.get_related_strings(&oversized, 10).is_empty());
    assert_eq!(legacy_count(u64::MAX), usize::MAX);
}
