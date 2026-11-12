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

#[test]
fn tracking_the_same_batch_twice_counts_it_once() {
    // A repeated tool call on an unchanged file must not double the counts.
    let tracker = StringTracker::new();
    let strings = vec![
        "hello world string".to_string(),
        "another one here".to_string(),
    ];
    tracker
        .track_strings_from_results(&strings, "/f", "h1", "analyze_file")
        .unwrap();
    tracker
        .track_strings_from_results(&strings, "/f", "h1", "analyze_file")
        .unwrap();
    assert_eq!(
        tracker
            .get_string_details("hello world string")
            .unwrap()
            .total_occurrences,
        1
    );
    // Another file with the same strings is a different batch.
    tracker
        .track_strings_from_results(&strings, "/g", "h2", "analyze_file")
        .unwrap();
    assert_eq!(
        tracker
            .get_string_details("hello world string")
            .unwrap()
            .total_occurrences,
        2
    );
}

#[test]
fn records_offsets_once_per_batch_key_and_clear_forgets_everything() {
    let tracker = StringTracker::new();
    let items = vec![("beacon string value".to_string(), 4096usize)];
    let first = tracker.track_strings_at(|| items.clone(), "/f", "h1", "search_strings", "min=4");
    assert_eq!((first.tracked, first.already_indexed), (1, false));
    let again = tracker.track_strings_at(
        || panic!("an indexed batch is not built again"),
        "/f",
        "h1",
        "search_strings",
        "min=4",
    );
    assert!(again.already_indexed);
    let entry = tracker.get_string_details("beacon string value").unwrap();
    assert!(matches!(
        entry.occurrences[0].context,
        StringContext::FileString { offset: Some(4096) }
    ));
    // A different option set is a new batch.
    assert!(
        !tracker
            .track_strings_at(|| items.clone(), "/f", "h1", "search_strings", "min=8")
            .already_indexed
    );

    tracker.clear();
    assert!(tracker.get_string_details("beacon string value").is_none());
    assert_eq!(tracker.get_statistics(None).total_unique_strings, 0);
    // After a clear the same batch can be indexed again.
    assert!(
        !tracker
            .track_strings_at(|| items.clone(), "/f", "h1", "search_strings", "min=4")
            .already_indexed
    );
}

#[test]
fn filtered_search_matches_values_then_applies_the_entry_filter() {
    let tracker = StringTracker::new();
    let items: Vec<(String, usize)> = [
        "http://evil.example.com/x",
        "plain words only here",
        "cmd.exe /c whoami",
    ]
    .iter()
    .enumerate()
    .map(|(i, s)| ((*s).to_string(), i * 100))
    .collect();
    tracker.track_strings_at(|| items.clone(), "/f", "h", "t", "k");
    let all = tracker.search_filtered(Some("EVIL"), None, 10, &|_| true);
    assert_eq!(all.len(), 1, "case-insensitive substring");
    let pattern = regex::Regex::new("^plain").unwrap();
    assert_eq!(
        tracker
            .search_filtered(None, Some(&pattern), 10, &|_| true)
            .len(),
        1
    );
    let suspicious = tracker.search_filtered(None, None, 10, &|e| e.is_suspicious);
    assert!(suspicious.iter().any(|e| e.value.contains("cmd.exe")));
    assert!(!suspicious.iter().any(|e| e.value.starts_with("plain")));
    assert_eq!(
        tracker.search_filtered(None, None, 1, &|_| true).len(),
        1,
        "limit"
    );
}

#[test]
fn a_filtered_search_inspects_every_tracked_value() {
    let tracker = StringTracker::new();
    // More values than any candidate cap, the only match sorting last.
    let items: Vec<(String, usize)> = (0..30_000)
        .map(|n| (format!("aaaa plain value {n:06}"), n))
        .chain(std::iter::once((
            "http://late.example.com/x".to_string(),
            99,
        )))
        .collect();
    tracker.track_strings_at(|| items, "/f", "h", "search_strings", "min=4");
    let urls = tracker.search_filtered(None, None, 10, &|entry| entry.categories.contains("url"));
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert_eq!(urls[0].value, "http://late.example.com/x");
}

#[test]
fn classify_does_not_depend_on_the_session_tracker_and_records_nothing() {
    let tracker = StringTracker::new();
    let entry = tracker.classify("http://evil.example.com/x").unwrap();
    assert!(entry.categories.contains("url"), "{:?}", entry.categories);
    assert_eq!(tracker.get_statistics(None).total_unique_strings, 0);
    assert!(tracker
        .get_string_details("http://evil.example.com/x")
        .is_none());
}

#[test]
fn two_paths_with_the_same_content_are_both_recorded() {
    let tracker = StringTracker::new();
    let items = vec![("shared string value".to_string(), 7usize)];
    for path in ["/copy_a", "/copy_b"] {
        let report =
            tracker.track_strings_at(|| items.clone(), path, "same", "search_strings", "min=4");
        assert!(!report.already_indexed, "{path}");
    }
    let entry = tracker.get_string_details("shared string value").unwrap();
    assert_eq!(entry.unique_files.len(), 2);
    assert_eq!(entry.total_occurrences, 2);
}

#[test]
fn a_file_tracked_by_one_route_is_not_counted_again_by_another() {
    let tracker = StringTracker::new();
    let strings = vec!["msftupdater.com".to_string()];
    tracker
        .track_strings_from_results(&strings, "/f", "h", "analyze_file")
        .unwrap();
    let report = tracker.track_strings_at(
        || vec![("msftupdater.com".to_string(), 12)],
        "/f",
        "h",
        "search_strings",
        "min=4",
    );
    assert!(report.tracked_by_other_route);
    let entry = tracker.get_string_details("msftupdater.com").unwrap();
    assert_eq!(entry.total_occurrences, 1);

    // The other order gives the same count.
    let other = StringTracker::new();
    other.track_strings_at(
        || vec![("msftupdater.com".to_string(), 12)],
        "/f",
        "h",
        "search_strings",
        "min=4",
    );
    other
        .track_strings_from_results(&strings, "/f", "h", "analyze_file")
        .unwrap();
    assert_eq!(
        other
            .get_string_details("msftupdater.com")
            .unwrap()
            .total_occurrences,
        1
    );
}

#[test]
fn a_full_tracker_reports_the_skipped_count_on_every_call() {
    let tracker = StringTracker::new();
    let filler: Vec<(String, usize)> = (0..StringTracker::CAPACITY)
        .map(|n| (format!("filler value {n:07}"), n))
        .collect();
    let first = tracker.track_strings_at(|| filler, "/big", "hb", "search_strings", "min=4");
    assert_eq!(first.skipped, 0);
    assert!(tracker.is_full());
    let items = vec![("one more value".to_string(), 1usize)];
    let first = tracker.track_strings_at(|| items.clone(), "/f", "h", "search_strings", "min=4");
    assert_eq!(first.skipped, 1);
    let again = tracker.track_strings_at(|| items.clone(), "/f", "h", "search_strings", "min=4");
    assert!(again.already_indexed);
    assert_eq!(again.skipped, 1, "the repeat still says values are missing");
}
