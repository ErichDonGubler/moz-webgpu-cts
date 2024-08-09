mod log_line_reader;

use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use format::lazy_format;
use log_line_reader::{
    LogLineReader, LogLineSpans, ParseOkTestError, TestLogLineParseError,
    TestLogLineParseErrorKind, TestPathParseError, TookParseError,
};
use miette::{IntoDiagnostic, LabeledSpan, Report, SourceSpan};

use crate::{wpt::path::Browser, AlreadyReportedToCommandline};

pub(crate) fn aggregate_timings_from_logs(
    browser: Browser,
    log_paths: Vec<PathBuf>,
) -> Result<(), AlreadyReportedToCommandline> {
    enum TestLogParserState {
        Ready,
        StartedTest {
            test_name: LogLineSpans,
            reported_subtest: bool,
        },
    }

    if log_paths.is_empty() {
        log::error!(concat!(
            "no log file(s) specified; ",
            "this command doesn't make sense without them!"
        ));
        return Err(AlreadyReportedToCommandline);
    }

    // TODO: Do 'em all in parallel!

    let log_path = log_paths.first().unwrap();
    let mut reader = LogLineReader::new(browser, BufReader::new(File::open(log_path).unwrap()));

    let mut buf = String::with_capacity(512);
    let mut errs = Vec::new();
    loop {
        buf.clear();
        errs.clear();
        let line_res = reader
            .next_log_line(&mut buf, &mut |e| errs.push(e))
            .map(|res| res.into_diagnostic());
        match line_res {
            Some(Ok(line)) => {
                assert!(errs.is_empty());
                log::info!("bro it works: {line:?}")
            }
            Some(Err(e)) => {
                for err in errs.drain(..) {
                    render_test_log_line_err(&log_path, &buf, err);
                }
                log::error!("{e}");
                return Err(AlreadyReportedToCommandline);
            }
            None => {
                assert!(errs.is_empty());
                break;
            }
        }
    }

    Ok(())
}

fn render_test_log_line_err(log_path: &Path, buf: &str, e: TestLogLineParseError) {
    impl From<LogLineSpans> for SourceSpan {
        fn from(value: LogLineSpans) -> Self {
            value.buf_slice_idx().into()
        }
    }

    let TestLogLineParseError { line_idx, kind } = e;
    let line_num = line_idx.checked_add(1).unwrap();
    // TODO: use `camino` paths, save everyone some pain 😭
    let log_and_line_prepend =
        lazy_format!("{log_path:?}:{line_num}: failed to parse `TEST` log line: ");
    let test_path_parse_labels = |err| {
        let TestPathParseError {
            discriminant_span,
            test_path_span,
            msg,
        } = err;
        vec![
            LabeledSpan::at(
                discriminant_span,
                "indicates that the test path will be started",
            ),
            LabeledSpan::new_primary_with_span(Some(msg), test_path_span),
        ]
    };
    let diagnostic = match kind {
        TestLogLineParseErrorKind::ParseTimestamp { source, span } => {
            miette::diagnostic!(
                labels = vec![LabeledSpan::new_primary_with_span(None, span)],
                "{log_and_line_prepend}{source}"
            )
        }
        TestLogLineParseErrorKind::UnrecognizedDiscriminant { span } => {
            let discriminant = span.get_from(&buf);
            miette::diagnostic!(
                labels = vec![LabeledSpan::new_primary_with_span(None, span)],
                "{log_and_line_prepend}unrecognized discriminant {discriminant:?}"
            )
        }
        TestLogLineParseErrorKind::ParseStartTestPath(inner) => miette::diagnostic!(
            labels = test_path_parse_labels(inner),
            "{log_and_line_prepend}failed to parse `START`ed test path"
        ),
        TestLogLineParseErrorKind::ParseOkTest(e) => match e {
            ParseOkTestError::SplitDivider { span } => {
                miette::diagnostic!(
                    labels = vec![LabeledSpan::new_primary_with_span(None, span)],
                    // TODO: share constant, probably via `Display`?
                    "{log_and_line_prepend}failed to find dividing split (` | `) between a presumed test path and `took` duration",
                )
            }
            ParseOkTestError::ParseTestPath { inner } => miette::diagnostic!(
                labels = test_path_parse_labels(inner),
                "{log_and_line_prepend}failed to parse `OK`'d test path"
            ),
            ParseOkTestError::ParseTook { inner } => {
                let log_and_line_prepend = lazy_format!("{log_and_line_prepend}`took` duration ");
                match inner {
                    TookParseError::ParseMillis { span, source } => miette::diagnostic!(
                        labels = vec![LabeledSpan::new_primary_with_span(
                            Some(source.to_string()),
                            span
                        )],
                        "{log_and_line_prepend}had invalid milliseconds count"
                    ),
                    TookParseError::ParseUnit { expected_ms_span } => miette::diagnostic!(
                        labels = vec![LabeledSpan::new_primary_with_span(
                            Some("expected here".to_owned()),
                            expected_ms_span
                        )],
                        "{log_and_line_prepend}of the form `took <count>ms` not found"
                    ),
                }
            }
        },
    }.with_help(concat!(
        "If this isn't a malformed edit of yours, it's likely a bug in `",
        env!("CARGO_BIN_NAME"),
        "`. You should file an issue upstream!"
    ));
    let diagnostic = Report::new(diagnostic).with_source_code(buf.to_owned());
    eprintln!("{diagnostic:?}")
}
