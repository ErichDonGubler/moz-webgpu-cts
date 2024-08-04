use std::{
    collections::BTreeMap,
    fmt::{Debug, Display},
    fs,
    hash::Hash,
    io::{self, BufReader},
    path::{Path, PathBuf},
    sync::{mpsc::channel, Arc},
};

use camino::Utf8PathBuf;
use enumset::EnumSetType;
use format::lazy_format;
use indexmap::IndexMap;
use miette::{IntoDiagnostic, Report, WrapErr};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use whippit::metadata::SectionHeader;

use crate::{
    report::{
        ExecutionReport, RunInfo, SubtestExecutionResult, TestExecutionEntry, TestExecutionResult,
    },
    taint_subtest_timeouts_by_suspicion,
    wpt::{
        metadata::{
            properties::{ExpandedPropertyValue, Expected, NonNormalizedPropertyValue},
            BuildProfile, File, FileProps, Platform, Subtest, SubtestOutcome, Test, TestOutcome,
            TestProps,
        },
        path::{Browser, TestEntryPath},
    },
    AlreadyReportedToCommandline,
};

pub(crate) mod should_update_expected;

#[derive(Debug, Default)]
pub(crate) struct Entry<Out>
where
    Out: EnumSetType,
{
    pub meta_props: Option<TestProps<Out>>,
    pub reported: NonNormalizedPropertyValue<Expected<Out>>,
}

#[derive(Debug, Default)]
pub(crate) struct TestEntry {
    pub entry: Entry<TestOutcome>,
    pub subtests: BTreeMap<String, Entry<SubtestOutcome>>,
}

#[derive(Debug)]
pub(crate) struct ProcessReportsArgs<'a> {
    pub browser: Browser,
    pub checkout: &'a Path,
    pub exec_report_paths: Vec<PathBuf>,
    pub preset: ReportProcessingPreset,
    pub on_missing_from_report: MissingFromReport,
    pub should_update_expected: &'a mut dyn should_update_expected::ShouldUpdateExpected,
    pub meta_files_by_path: IndexMap<Arc<PathBuf>, File>,
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum ReportProcessingPreset {
    ResetContradictoryOutcomes,
    MergeOutcomes,
    ResetAllOutcomes,
    MigrateTestStructure,
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum MissingFromReport {
    Delete(Log),
    Keep(Log),
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Log {
    Silent,
    Info,
    Warn,
}

impl Log {
    fn log<A: AsRef<str>>(&self, msg: A) {
        match self {
            Log::Silent => {}
            Log::Info => log::info!("{}", msg.as_ref()),
            Log::Warn => log::warn!("{}", msg.as_ref()),
        }
    }
}

#[derive(Debug, Default)]
struct EntryByCtsPath<'a> {
    metadata_path: Option<TestEntryPath<'a>>,
    reported_path: Option<TestEntryPath<'a>>,
    entry: TestEntry,
}

fn cts_path(test_entry_path: &TestEntryPath<'_>) -> Option<String> {
    test_entry_path
        .test_entry
        .variant
        .as_ref()
        .filter(|v| v.starts_with("?q=webgpu:"))
        .map(|v| v.strip_prefix("?q=").unwrap().to_owned())
        .filter(|_q| test_entry_path.spec_path.path.ends_with("cts.https.html"))
}

fn accumulate<Out>(
    recorded: &mut NonNormalizedPropertyValue<Expected<Out>>,
    platform: Platform,
    build_profile: BuildProfile,
    reported_outcome: Out,
) where
    Out: Default + EnumSetType + Hash,
{
    match recorded.entry(platform).or_default().entry(build_profile) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(Expected::permanent(reported_outcome));
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            *entry.get_mut() |= reported_outcome
        }
    }
}

/// Reconciles `meta_props` with `reported` if they match
/// `implementation_status_filter`.
///
/// For subtests, `parent_implementation_status` should be specified so the
/// parent test's implementation status can be used for filtering.
#[allow(clippy::type_complexity)]
fn reconcile<Out>(
    meta_props: &mut TestProps<Out>,
    reported: NonNormalizedPropertyValue<Expected<Out>>,
    preset: ReportProcessingPreset,
    should_update_expected: &mut dyn FnMut(
        &TestProps<Out>,
        &NonNormalizedPropertyValue<Expected<Out>>,
        (Platform, BuildProfile),
    ) -> bool,
) where
    Out: Debug + Default + EnumSetType,
{
    let reconciled = {
        let meta_expected = meta_props.expected.unwrap_or_default();

        let resolve: fn(Expected<_>, Option<Expected<_>>) -> _ = match preset {
            ReportProcessingPreset::ResetAllOutcomes => |_meta, rep| rep.unwrap_or_default(),
            ReportProcessingPreset::ResetContradictoryOutcomes => {
                |meta, rep| rep.filter(|rep| !meta.is_superset(rep)).unwrap_or(meta)
            }
            ReportProcessingPreset::MergeOutcomes => |meta, rep| match rep {
                Some(rep) => meta | rep,
                None => meta,
            },
            ReportProcessingPreset::MigrateTestStructure => |meta, _rep| meta,
        };

        ExpandedPropertyValue::from_query(|platform, build_profile| {
            let key = (platform, build_profile);
            if should_update_expected(meta_props, &reported, key) {
                let reported = reported
                    .get(&platform)
                    .and_then(|rep| rep.get(&build_profile))
                    .copied();
                resolve(meta_expected[key], reported)
            } else {
                meta_expected[key]
            }
        })
    };
    meta_props.expected = Some(reconciled);
}

pub(crate) fn process_reports(
    args: ProcessReportsArgs<'_>,
) -> Result<BTreeMap<PathBuf, File>, AlreadyReportedToCommandline> {
    let ProcessReportsArgs {
        browser,
        checkout,
        exec_report_paths,
        preset,
        on_missing_from_report,
        should_update_expected,
        meta_files_by_path,
    } = args;

    let mut file_props_by_file = IndexMap::<Utf8PathBuf, FileProps>::default();
    let mut entries_by_cts_path = IndexMap::<String, EntryByCtsPath<'_>>::default();
    let mut other_entries_by_test = IndexMap::<TestEntryPath<'_>, TestEntry>::default();
    let old_meta_file_paths = meta_files_by_path.keys().cloned().collect::<Vec<_>>();

    log::debug!("loading metadata for comparison to reports…");
    for (path, file) in meta_files_by_path {
        let File { properties, tests } = file;

        let file_rel_path = path.strip_prefix(checkout).unwrap();

        file_props_by_file.insert(
            Utf8PathBuf::from(file_rel_path.to_str().unwrap()),
            properties,
        );

        for (SectionHeader(name), test) in tests {
            let Test {
                properties,
                subtests,
            } = test;

            let test_entry_path =
                TestEntryPath::from_metadata_test(browser, file_rel_path, &name).unwrap();

            let freak_out_do_nothing =
                |what: &dyn Display| log::error!("hoo boy, not sure what to do yet: {what}");

            let mut reported_dupe_already = false;
            let mut dupe_err = || {
                if !reported_dupe_already {
                    freak_out_do_nothing(&format_args!(
                        concat!(
                            "duplicate entry for {:?}",
                            "discarding previous entries with ",
                            "this and further dupes"
                        ),
                        test_entry_path
                    ))
                }
                reported_dupe_already = true;
            };

            let TestEntry {
                entry: test_entry,
                subtests: subtest_entries,
            } = if let Some(cts_path) = cts_path(&test_entry_path) {
                let entry = entries_by_cts_path.entry(cts_path).or_default();
                if let Some(_old) = entry
                    .metadata_path
                    .replace(test_entry_path.clone().into_owned())
                {
                    dupe_err();
                }
                &mut entry.entry
            } else {
                other_entries_by_test
                    .entry(test_entry_path.clone().into_owned())
                    .or_default()
            };

            let test_entry_path = &test_entry_path;

            if let Some(_old) = test_entry.meta_props.replace(properties) {
                dupe_err();
            }

            for (SectionHeader(subtest_name), subtest) in subtests {
                let Subtest { properties } = subtest;
                let subtest_entry = subtest_entries.entry(subtest_name.clone()).or_default();
                if let Some(_old) = subtest_entry.meta_props.replace(properties) {
                    if !reported_dupe_already {
                        freak_out_do_nothing(&format_args!(
                            concat!(
                                "duplicate subtest in {:?} named {:?}, ",
                                "discarding previous entries with ",
                                "this and further dupes"
                            ),
                            test_entry_path, subtest_name
                        ));
                    }
                }
            }
        }
    }

    log::debug!("gathering reported test outcomes for reconciliation with metadata…");

    let using_reports = !exec_report_paths.is_empty();

    let (exec_reports_sender, exec_reports_receiver) = channel();
    exec_report_paths
        .into_par_iter()
        .for_each_with(exec_reports_sender, |sender, path| {
            let res = fs::File::open(&path)
                .map(BufReader::new)
                .map_err(Report::msg)
                .wrap_err("failed to open file")
                .and_then(|reader| {
                    serde_json::from_reader::<_, ExecutionReport>(reader)
                        .map(Some)
                        .or_else(|e| {
                            if e.is_eof() && matches!((e.line(), e.column()), (1, 0)) {
                                Ok(None)
                            } else {
                                Err(e)
                            }
                        })
                        .into_diagnostic()
                        .wrap_err("failed to parse JSON")
                })
                .wrap_err_with(|| {
                    format!(
                        "failed to read WPT execution report from {}",
                        path.display()
                    )
                })
                .map(|parsed| (path, parsed))
                .map_err(|e| {
                    log::error!("{e:?}");
                    AlreadyReportedToCommandline
                });
            let _ = sender.send(res);
        });

    for res in exec_reports_receiver {
        let (path, exec_report) = res?;

        let exec_report = match exec_report {
            Some(some) => some,
            None => {
                log::warn!("empty report found: {}", path.display());
                continue;
            }
        };

        let ExecutionReport {
            run_info:
                RunInfo {
                    platform,
                    build_profile,
                },
            entries,
        } = exec_report;

        for entry in entries {
            let TestExecutionEntry { test_name, result } = entry;

            let test_entry_path =
                TestEntryPath::from_execution_report(browser, &test_name).unwrap();
            let TestEntry {
                entry: test_entry,
                subtests: subtest_entries,
            } = if let Some(cts_path) = cts_path(&test_entry_path) {
                let entry = entries_by_cts_path.entry(cts_path).or_default();
                if let Some(old) = entry
                    .reported_path
                    .replace(test_entry_path.clone().into_owned())
                {
                    if old != test_entry_path {
                        log::warn!(
                            concat!(
                                "found test execution entry containing the same ",
                                "CTS test path as another, ",
                                "discarding previous entries with ",
                                "this and further dupes; entries:\n",
                                "older: {:#?}\n",
                                "newer: {:#?}\n",
                            ),
                            old,
                            test_entry_path
                        )
                    }
                }
                &mut entry.entry
            } else {
                other_entries_by_test
                    .entry(test_entry_path.clone().into_owned())
                    .or_default()
            };

            let (reported_outcome, reported_subtests) = match result {
                TestExecutionResult::Complete { outcome, subtests } => (outcome, subtests),
                TestExecutionResult::JobMaybeTimedOut { status, subtests } => {
                    if !status.is_empty() {
                        log::warn!(
                            concat!(
                                "expected an empty `status` field for {:?}, ",
                                "but found the {:?} status"
                            ),
                            test_entry_path,
                            status,
                        )
                    }
                    (TestOutcome::Timeout, subtests)
                }
            };

            accumulate(
                &mut test_entry.reported,
                platform,
                build_profile,
                reported_outcome,
            );

            for reported_subtest in reported_subtests {
                let SubtestExecutionResult {
                    subtest_name,
                    outcome,
                } = reported_subtest;

                accumulate(
                    &mut subtest_entries
                        .entry(subtest_name.clone())
                        .or_default()
                        .reported,
                    platform,
                    build_profile,
                    outcome,
                );
            }
        }
    }

    log::debug!("metadata and reports gathered, now reconciling outcomes…");

    let entries_by_cts_path = entries_by_cts_path.into_iter().map(|(_name, entry)| {
        let EntryByCtsPath {
            metadata_path,
            reported_path,
            entry,
        } = entry;
        let output_path = if let Some((meta, rep)) = metadata_path
            .as_ref()
            .zip(reported_path.as_ref())
            .filter(|(meta, rep)| meta != rep)
        {
            log::info!(
                concat!(
                    "metadata path for test is different from ",
                    "reported execution; relocating…\n",
                    "…metadata: {:#?}\n",
                    "…reported: {:#?}\n"
                ),
                meta,
                rep
            );
            reported_path
        } else {
            metadata_path.or(reported_path)
        };

        (
            output_path.expect(concat!(
                "internal error: CTS path entry created without at least one ",
                "report or metadata path specified"
            )),
            entry,
        )
    });
    let recombined_tests_iter = entries_by_cts_path.chain(other_entries_by_test).filter_map(
        |(test_entry_path, test_entry)| {
            let TestEntry {
                entry:
                    Entry {
                        meta_props: properties,
                        reported: mut test_reported,
                    },
                subtests: subtest_entries,
            } = test_entry;

            if properties.is_none() {
                log::info!("new test entry: {test_entry_path:?}")
            }

            if test_reported.is_empty() && using_reports {
                let test_entry_path = &test_entry_path;
                let msg = lazy_format!("no entries found in reports for {:?}", test_entry_path);
                match preset {
                    ReportProcessingPreset::MergeOutcomes => log::warn!("{msg}"),
                    ReportProcessingPreset::ResetAllOutcomes
                    | ReportProcessingPreset::ResetContradictoryOutcomes => {
                        log::warn!("removing metadata after {msg}");
                        return None;
                    }
                    ReportProcessingPreset::MigrateTestStructure => {
                        log::info!("removing metadata after {msg}");
                        return None;
                    }
                }
            }

            let mut properties = properties.unwrap_or_default();

            for (platform, build_profile, reported) in
                test_reported.iter_mut().flat_map(|(p, by_bp)| {
                    by_bp
                        .iter_mut()
                        .map(move |(bp, reported)| (p, bp, reported))
                })
            {
                let skip = TestOutcome::Skip;
                // Ignore `SKIP` outcomes if we have non-`SKIP` outcomes here.
                //
                // Do this so that test runs whose coverage _in aggregate_ includes actual
                // runs on this test are viable for processing. Otherwise, we'd have `SKIP`
                // outcomes be included that aren't actually wanted.
                if *reported != skip {
                    let skip = skip.into();
                    if reported.inner().is_superset(skip) {
                        log::debug!(
                            concat!(
                                "encountered `{}` among other outcomes ",
                                "in aggregation of reported test outcomes ",
                                "for {:?} with platform {:?} and build profile {:?}, ",
                                " removing with the assumption that ",
                                "this is an artifact of disjoint test runs"
                            ),
                            skip,
                            test_entry_path,
                            platform,
                            build_profile,
                        );
                        *reported = Expected::new(reported.inner() & !skip)
                            .expect("internal error: empty non-`SKIP` superset");
                    }
                }
            }

            reconcile(
                &mut properties,
                test_reported,
                preset,
                &mut |meta_props, reported, key| {
                    should_update_expected.test(meta_props, reported, key)
                },
            );

            let subtests = subtest_entries
                .into_iter()
                .filter_map(|(subtest_name, subtest)| {
                    let subtest_name = SectionHeader(subtest_name);

                    let Entry {
                        meta_props: subtest_properties,
                        reported: subtest_reported,
                    } = subtest;

                    if subtest_reported.is_empty() && using_reports {
                        let test_entry_path = &test_entry_path;
                        let subtest_name = &subtest_name;
                        let msg = lazy_format!(
                            "no subtest entries found in reports for {:?}, subtest {:?}",
                            test_entry_path,
                            subtest_name,
                        );
                        match on_missing_from_report {
                            MissingFromReport::Delete(log) => {
                                log.log(format!("removing metadata after {msg}"));
                                return None;
                            }
                            MissingFromReport::Keep(log) => log.log(msg.to_string()),
                        }
                    }

                    let mut subtest_properties = subtest_properties.unwrap_or_default();
                    reconcile(
                        &mut subtest_properties,
                        subtest_reported,
                        preset,
                        &mut |meta_props, reported, key| {
                            should_update_expected.subtest(meta_props, reported, &properties, key)
                        },
                    );
                    for (_, expected) in subtest_properties.expected.as_mut().unwrap().iter_mut() {
                        taint_subtest_timeouts_by_suspicion(expected);
                    }

                    Some((
                        subtest_name,
                        Subtest {
                            properties: subtest_properties,
                        },
                    ))
                })
                .collect::<BTreeMap<_, _>>();

            Some((test_entry_path, (properties, subtests)))
        },
    );

    log::debug!("outcome reconciliation complete, gathering tests back into new metadata files…");

    let mut files = BTreeMap::<PathBuf, File>::new();
    for (test_entry_path, (properties, subtests)) in recombined_tests_iter {
        let name = test_entry_path.test_name().to_string();
        let rel_path = Utf8PathBuf::from(test_entry_path.rel_metadata_path().to_string());
        let path = checkout.join(&rel_path);
        let file = files.entry(path).or_insert_with(|| File {
            properties: file_props_by_file
                .get(&rel_path)
                .cloned()
                .unwrap_or_else(|| {
                    log::warn!("creating new metadata file for `{rel_path}`");
                    Default::default()
                }),
            tests: Default::default(),
        });
        file.tests.insert(
            SectionHeader(name),
            Test {
                properties,
                subtests,
            },
        );
    }

    for old_meta_file_path in old_meta_file_paths {
        files
            .entry(Arc::into_inner(old_meta_file_path).unwrap())
            .or_default();
    }

    files.retain(|path, file| {
        let is_empty = file.tests.is_empty();
        if is_empty {
            log::info!("removing now-empty metadata file {}", path.display());
            match fs::remove_file(path) {
                Ok(()) => (),
                Err(e) => match e.kind() {
                    io::ErrorKind::NotFound => (),
                    _ => log::error!(
                        "failed to remove now-empty metadata file {}",
                        path.display()
                    ),
                },
            }
        }
        !is_empty
    });

    Ok(files)
}
