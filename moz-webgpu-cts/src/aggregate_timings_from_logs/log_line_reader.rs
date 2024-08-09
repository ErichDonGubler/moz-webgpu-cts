use std::{
    io::{self, BufRead},
    ops::Range,
    time::Duration,
};

use chrono::{DateTime, FixedOffset};
use miette::Diagnostic;
use whippit::reexport::chumsky::{
    error::{EmptyErr, Simple},
    extra::{Full, ParserExtra},
    input::Input,
    primitive::{any, just},
    span::SimpleSpan,
    text::{ascii, digits},
    IterParser, Parser,
};

use crate::wpt::path::{Browser, TestEntryPath};

pub(super) struct LogLineReader<R> {
    browser: Browser,
    next_line_idx: u64,
    reader: R,
}

impl<R> LogLineReader<R> {
    pub fn new(browser: Browser, reader: R) -> Self {
        Self {
            browser,
            next_line_idx: 1,
            reader,
        }
    }
}

impl<R> LogLineReader<R>
where
    R: BufRead,
{
    pub fn next_log_line<'a>(
        &mut self,
        buf: &'a mut String,
        test_log_line_parse_error_sink: &mut dyn FnMut(TestLogLineParseError),
    ) -> Option<Result<LogLine, LogLineReadError>> {
        let line_offset_in_buf = buf.len();
        let mut should_keep_line = false;
        let ret = self.read_line(buf)?.and_then(|(line, line_idx)| {
            let (res, saved_spans) = classify_log_line(
                self.browser,
                line_idx,
                line,
                line_offset_in_buf,
                test_log_line_parse_error_sink,
            );
            should_keep_line = saved_spans;
            let kind = res?;
            Ok(LogLine { line_idx, kind })
        });
        if !should_keep_line {
            buf.truncate(line_offset_in_buf);
        }
        Some(ret)
    }

    fn read_line<'a>(
        &mut self,
        buf: &'a mut String,
    ) -> Option<Result<(&'a str, u64), LogLineReadError>> {
        let Self {
            next_line_idx,
            reader,
            ..
        } = self;

        let start = buf.len();
        match reader
            .read_line(buf)
            .map_err(|source| LogLineReadError::Io { source })
        {
            Ok(0) => None,
            Ok(bytes_read) => {
                let extracted = match bytes_read {
                    0 => None,
                    _ => Some(Ok((&buf[start..buf.len()], *next_line_idx))),
                };
                *next_line_idx = next_line_idx.checked_add(1).unwrap();
                extracted
            }
            Err(e) => Some(Err(e)),
        }
    }
}

#[derive(Debug, Diagnostic, thiserror::Error)]
#[error("failed to parse log line")]
pub(super) enum LogLineReadError {
    Io {
        source: io::Error,
    },
    ClassifyTestLogLine {
        #[from]
        source: CheckErrorSink,
    },
}

#[derive(Clone, Debug)]
pub(super) struct LogLine {
    pub line_idx: u64,
    pub kind: LogLineKind,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) enum LogLineKind {
    Test(TestLogLine),
    Other,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct TestLogLine {
    pub timestamp: DateTime<FixedOffset>,
    pub kind: TestLogLineKind,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct LogLineSpans {
    offset_from_start_of_line: usize,
    offset_in_buf: usize,
    length: usize,
}

impl LogLineSpans {
    pub fn buf_slice_idx(&self) -> Range<usize> {
        let &Self {
            offset_in_buf,
            length,
            ..
        } = self;
        offset_in_buf..(offset_in_buf + length)
    }

    #[track_caller]
    pub fn get_from<'a>(&self, s: &'a str) -> &'a str {
        s.get(self.buf_slice_idx()).unwrap()
    }

    #[track_caller]
    pub fn truncate_before_in(&self, s: &mut String) {
        s.truncate(self.offset_in_buf)
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) enum TestLogLineKind {
    StartTest {
        test_name: LogLineSpans,
    },
    FinishTestExpected {
        test_name: LogLineSpans,
        took: Duration,
    },
    FinishSubtest {
        test_name: LogLineSpans,
        subtest_name: LogLineSpans,
    },
    FinishTestUnexpected {
        test_name: LogLineSpans,
    },
    InfoTook {
        took: Duration,
    },
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct TestLogLineParseError {
    pub line_idx: u64,
    pub kind: TestLogLineParseErrorKind,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) enum TestLogLineParseErrorKind {
    ParseTimestamp {
        source: chrono::ParseError,
        span: LogLineSpans,
    },
    UnrecognizedDiscriminant {
        span: LogLineSpans,
    },
    ParseStartTestPath(TestPathParseError),
    ParseOkTest(ParseOkTestError),
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) enum ParseOkTestError {
    SplitDivider { span: LogLineSpans },
    ParseTestPath { inner: TestPathParseError },
    ParseTook { inner: TookParseError },
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct TestPathParseError {
    pub discriminant_span: LogLineSpans,
    pub test_path_span: LogLineSpans,
    pub msg: String,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) enum TookParseError {
    ParseUnit {
        expected_ms_span: LogLineSpans,
    },
    ParseMillis {
        span: LogLineSpans,
        source: std::num::ParseIntError,
    },
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("see above errors for more details")]
pub(super) struct CheckErrorSink;

fn classify_log_line<'a>(
    browser: Browser,
    line_idx: u64,
    s: &'a str,
    slice_start: usize, // TODO: maybe confusing with `s`' start?
    unrecoverable_err_sink: &'a mut dyn FnMut(TestLogLineParseError),
) -> (Result<LogLineKind, CheckErrorSink>, bool) {
    fn mozlog_test_message_section_divider<'a, I, E>() -> impl Parser<'a, I, (), E> + Copy + Clone
    where
        I: Input<'a, Token = char>,
        E: ParserExtra<'a, I>,
    {
        just(" | ").to(())
    }
    let test_log_line = {
        // i.e., something of the form `[task 2024-08-02T22:11:54.874Z] `
        let first_log_layer = any::<
            &str,
            Full<Simple<char>, (&mut bool, &mut dyn FnMut(TestLogLineParseError)), ()>,
        >() // TODO: ew, dis bad, better plz?
        .and_is(just("]").not())
        .repeated()
        .to_slice()
        .map_with(|raw, e| (raw, e.span()))
        .delimited_by(just("[task "), just("] "));

        // i.e., something of the form `22:11:54     INFO - `
        let second_log_layer = any()
            .repeated()
            .exactly(2)
            .separated_by(just(":"))
            .exactly(3)
            .then(just("     INFO - "))
            .ignored();

        let mozlog_test_message_layer = just("TEST-")
            .ignore_then(ascii::ident().map_with(|ident, e| (ident, e.span())))
            .then_ignore(mozlog_test_message_section_divider());

        first_log_layer
            .then_ignore(second_log_layer)
            .then(mozlog_test_message_layer)
            .then(
                any()
                    .repeated()
                    .to_slice()
                    .map_with(|rest, e| (rest, e.span())),
            )
            .map_with(
                move |(
                    ((raw_timestamp, timestamp_span), (discriminant, discriminant_span)),
                    (rest, rest_span),
                ),
                      e| {
                    let (should_save_spans, unrecoverable_err_sink) = e.state();

                    let mut save_span = |simple_span: SimpleSpan| {
                        **should_save_spans = true;
                        LogLineSpans {
                            offset_from_start_of_line: simple_span.start,
                            offset_in_buf: slice_start + simple_span.start,
                            length: simple_span.end - simple_span.start,
                        }
                    };

                    let mut unrecoverable_err_sink =
                        |kind| unrecoverable_err_sink(TestLogLineParseError { line_idx, kind });

                    let timestamp = match DateTime::parse_from_rfc3339(raw_timestamp) {
                        Ok(ok) => Some(ok),
                        Err(source) => {
                            unrecoverable_err_sink(TestLogLineParseErrorKind::ParseTimestamp {
                                span: save_span(timestamp_span),
                                source,
                            });
                            None
                        }
                    };

                    let kind = 'kind: {
                        match discriminant {
                            "START" => {
                                if let Err(e) = TestEntryPath::from_execution_report(browser, rest)
                                {
                                    unrecoverable_err_sink(
                                        TestLogLineParseErrorKind::ParseStartTestPath(
                                            TestPathParseError {
                                                discriminant_span: save_span(discriminant_span),
                                                test_path_span: save_span(rest_span),
                                                msg: e.to_string(),
                                            },
                                        ),
                                    );
                                    None
                                } else {
                                    Some(TestLogLineKind::StartTest {
                                        test_name: save_span(rest_span),
                                    })
                                }
                            }
                            "OK" => {
                                let rest = rest.map_span(|span| {
                                    SimpleSpan::new(
                                        rest_span.start + span.start,
                                        rest_span.start + span.end,
                                    )
                                });
                                let [(test_path, test_path_span), (took_section, took_span)] = {
                                    let res = any::<_, Full<Simple<char>, &str, ()>>()
                                        .and_is(mozlog_test_message_section_divider().not())
                                        .repeated()
                                        .to_slice()
                                        .map_with(|section, e| (section, e.span()))
                                        .separated_by(mozlog_test_message_section_divider())
                                        .collect_exactly()
                                        .parse(rest)
                                        .into_result()
                                        .map_err(|_e| {
                                            unrecoverable_err_sink(
                                                TestLogLineParseErrorKind::ParseOkTest(
                                                    ParseOkTestError::SplitDivider {
                                                        span: save_span(rest_span),
                                                    },
                                                ),
                                            );
                                            CheckErrorSink
                                        });
                                    match res {
                                        Ok(ok) => ok,
                                        Err(CheckErrorSink) => break 'kind None,
                                    }
                                };

                                if let Err(e) =
                                    TestEntryPath::from_execution_report(browser, test_path)
                                {
                                    unrecoverable_err_sink(TestLogLineParseErrorKind::ParseOkTest(
                                        ParseOkTestError::ParseTestPath {
                                            inner: TestPathParseError {
                                                discriminant_span: save_span(discriminant_span),
                                                test_path_span: save_span(test_path_span),
                                                msg: e.to_string(),
                                            },
                                        },
                                    ));
                                    break 'kind None;
                                }

                                let took_section = took_section.map_span(|span| {
                                    SimpleSpan::new(
                                        took_span.start + span.start,
                                        took_span.start + span.end,
                                    )
                                });

                                let took = {
                                    let took_res = digits::<_, _, Full<EmptyErr, &str, ()>>(10)
                                        .to_slice()
                                        .map_with(|millis, e| (millis, e.span()))
                                        .delimited_by(just("took "), just("ms"))
                                        .parse(took_section)
                                        .into_result()
                                        .map_err(|_e| TookParseError::ParseUnit {
                                            expected_ms_span: save_span(took_span),
                                        })
                                        .and_then(|(millis, millis_span)| {
                                            millis.parse().map(Duration::from_millis).map_err(
                                                |source| TookParseError::ParseMillis {
                                                    span: save_span(millis_span),
                                                    source,
                                                },
                                            )
                                        })
                                        .map_err(|inner| {
                                            TestLogLineParseErrorKind::ParseOkTest(
                                                ParseOkTestError::ParseTook { inner },
                                            )
                                        });
                                    match took_res {
                                        Ok(some) => some,
                                        Err(e) => {
                                            unrecoverable_err_sink(e);
                                            break 'kind None;
                                        }
                                    }
                                };

                                Some(TestLogLineKind::FinishTestExpected {
                                    test_name: save_span(test_path_span),
                                    took,
                                })
                            }
                            _ => {
                                unrecoverable_err_sink(
                                    TestLogLineParseErrorKind::UnrecognizedDiscriminant {
                                        span: save_span(discriminant_span.clone()),
                                    },
                                );
                                None
                            }
                        }
                    };
                    match (timestamp, kind) {
                        (Some(timestamp), Some(kind)) => {
                            Ok(LogLineKind::Test(TestLogLine { timestamp, kind }))
                        }
                        _ => Err(CheckErrorSink),
                    }
                },
            )
    };

    let mut should_save_spans = false;
    let res = test_log_line
        .parse_with_state(s, &mut (&mut should_save_spans, unrecoverable_err_sink))
        .into_output()
        .unwrap_or(Ok(LogLineKind::Other));
    (res, should_save_spans)
}

#[test]
fn classify_good_lines() {
    macro_rules! assert_good_parse_eq {
        ($line:expr, $should_save_spans:expr, $expected:expr) => {
            let mut errs = vec![];
            let res = classify_log_line(Browser::Firefox, 0, $line, 0, &mut |e| errs.push(e));
            if !errs.is_empty() {
                for err in &errs {
                    eprintln!("got unexpected test log line error: {err:#?}");
                }
            }
            assert_eq!(res, (Ok($expected), $should_save_spans));
            assert!(errs.is_empty());
        };
    }

    let line = "[task 2024-08-02T22:11:54.874Z] 22:11:54     INFO - TEST-START | /_mozilla/webgpu/cts/webgpu/shader/validation/decl/var/cts.https.html?q=webgpu:shader,validation,decl,var:initializer_kind:*";
    assert_good_parse_eq!(
        line,
        true,
        LogLineKind::Test(TestLogLine {
            timestamp: DateTime::parse_from_rfc3339("2024-08-02T22:11:54.874Z").unwrap(),
            kind: TestLogLineKind::StartTest {
                test_name: LogLineSpans {
                    offset_from_start_of_line: 65,
                    offset_in_buf: 65,
                    length: 124,
                }
            }
        })
    );

    let line = "[task 2024-08-02T22:17:15.803Z] 22:17:15     INFO - TEST-OK | /_mozilla/webgpu/cts/webgpu/api/operation/shader_module/compilation_info/cts.https.html?q=webgpu:api,operation,shader_module,compilation_info:getCompilationInfo_returns:* | took 9443ms";
    assert_good_parse_eq!(
        line,
        true,
        LogLineKind::Test(TestLogLine {
            timestamp: DateTime::parse_from_rfc3339("2024-08-02T22:17:15.803Z").unwrap(),
            kind: TestLogLineKind::FinishTestExpected {
                test_name: LogLineSpans {
                    offset_from_start_of_line: 62,
                    offset_in_buf: 62,
                    length: 170,
                },
                took: Duration::from_millis(9443),
            },
        })
    );
}

#[test]
fn classify_bad_lines() {
    let mut errs = Vec::new();
    macro_rules! assert_errs {
        ($line:expr, $should_save_spans:expr, $errs:expr) => {
            errs.clear();
            assert_eq!(
                classify_log_line(Browser::Firefox, 0, $line, 0, &mut |e| errs.push(e)),
                (Err(CheckErrorSink), $should_save_spans)
            );
            assert_eq!(errs, $errs);
        };
    }

    let line =
        "[task 2024-08-02T22:11:54.874Z] 22:11:54     INFO - TEST-DERP | /valid/test/path.https.html";
    assert_errs!(
        line,
        true,
        vec![TestLogLineParseError {
            line_idx: 0,
            kind: TestLogLineParseErrorKind::UnrecognizedDiscriminant {
                span: LogLineSpans {
                    offset_from_start_of_line: 57,
                    offset_in_buf: 57,
                    length: 4,
                }
            }
        }]
    );

    let line =
        "[task 2024-08-02T22:11:54.874Z] 22:11:54     INFO - TEST-START | bruh idk this ain't valid";
    assert_errs!(
        line,
        true,
        vec![TestLogLineParseError {
            line_idx: 0,
            kind: TestLogLineParseErrorKind::ParseStartTestPath(TestPathParseError {
                discriminant_span: LogLineSpans {
                    offset_from_start_of_line: 57,
                    offset_in_buf: 57,
                    length: 5,
                },
                test_path_span: LogLineSpans {
                    offset_from_start_of_line: 65,
                    offset_in_buf: 65,
                    length: 25,
                },
                msg: crate::wpt::path::ExecutionReportPathError {
                    test_url_path: "bruh idk this ain't valid"
                }
                .to_string()
            })
        }]
    );
}
