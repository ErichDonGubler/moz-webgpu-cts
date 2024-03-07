//! Contains data structures and logic for constructing them by parsing from . The main entry
//! point for this module is the [`File`] API.
//!
//! Documentation for types in this module refer liberally to the [WPT metadata format],
//! particularly the [`Web-Platform-Tests Metadata` section]. It is recommended that you
//! familiarize yourself with this document, if you plan to use this API.
//!
//! [WPT metadata format]: https://web-platform-tests.org/tools/wptrunner/docs/expectation.html#metadata-format
//! [`Web-Platform-Tests Metadata` section]: https://web-platform-tests.org/tools/wptrunner/docs/expectation.html#web-platform-tests-metadata

#[cfg(test)]
use {
    crate::metadata::properties::unstructured::{
        UnstructuredFile, UnstructuredSubtest, UnstructuredTest,
    },
    insta::assert_debug_snapshot,
};

use std::fmt::{self, Debug, Display};

use chumsky::{
    extra::Full,
    input::Emitter,
    prelude::Rich,
    primitive::{any, choice, custom, end, group, just},
    recovery::via_parser,
    span::SimpleSpan,
    text::{inline_whitespace, newline},
    IterParser, Parser,
};
use format::lazy_format;

use self::properties::{Properties, PropertiesParseHelper};

pub mod properties;

/// An error emitted by [`File::parser`] and [other WPT metadata parsing logic][self].
pub type ParseError<'a> = Full<Rich<'a, char>, (), ()>;

/// Behavior that needs to be defined to parse [the WPT metadata format][self] with
/// [`file_parser`].
///
/// If you don't have any opinions for an implementation of your own, you can use the
/// [`properties::unstructured`] API (gated behind the `unstructured` feature) for minimally
/// structured data that is maximally permissive in its parsing.
///
/// N.B. that you should not rely solely on data represented in this structure to compute test
/// metadata for test execution. It is _not_ complete by itself, because WPT metadata properties
/// can be layered across multiple sources (i.e., [`__dir__.ini`] files exist).
///
/// [`__dir__.ini`]: https://web-platform-tests.org/tools/wptrunner/docs/expectation.html#directory-metadata
pub trait File<'a>
where
    Self: Default,
{
    type Properties: Properties<'a>;
    type Tests: Tests<'a>;

    fn new(properties: Self::Properties, tests: Self::Tests) -> Self;
}

/// Returns a parser for a single [`File`] written in the [WPT metadata format][self].
///
/// No attempt is made to reconcile the provided string with additional layers of
/// configuration. See [`File`] for more details.
pub fn file_parser<'a, F>() -> impl Parser<'a, &'a str, F, ParseError<'a>>
where
    F: File<'a>,
{
    enum Item<T, P> {
        Property(P),
        Test(T),
    }
    choice((
        test_parser().map(Item::Test).labelled("test section"),
        F::Properties::property_parser(&mut PropertiesParseHelper::new(0))
            .map(Item::Property)
            .labelled("file property"),
    ))
    .padded_by(filler())
    .map_with(|test, e| (e.span(), test))
    .repeated()
    .collect::<Vec<_>>()
    .validate(|parsed_tests, _e, emitter| {
        let mut properties = F::Properties::default();
        let mut tests = F::Tests::default();
        for (span, item) in parsed_tests {
            match item {
                Item::Test((name, test)) => {
                    if let Some(name) = name {
                        tests.add_test(name, test, span, emitter)
                    } else {
                        // Presumably we applied recovery and emitted an error, so skip it.
                    }
                }
                Item::Property(prop) => {
                    if let Some(prop) = prop {
                        properties.add_property(prop, emitter)
                    } else {
                        // Presumably we applied recovery and emitted an error, so skip it.
                    }
                }
            }
        }
        F::new(properties, tests)
    })
}

fn filler<'a>() -> impl Parser<'a, &'a str, (), ParseError<'a>> {
    choice((comment(0).ignored(), newline())).repeated()
}

#[test]
fn smoke_parser() {
    let file_parser = UnstructuredFile::parser;

    assert_debug_snapshot!(
        file_parser().parse(""),
        @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {},
            },
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(file_parser().parse("[hoot]"), @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "hoot": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 0..6,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(file_parser().parse("[blarg]\n"), @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "blarg": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 0..8,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(file_parser().parse("[blarg]\n[stuff]"), @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "blarg": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 0..8,
                    },
                    "stuff": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 8..15,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(file_parser().parse("\n[blarg]\n[stuff]\n"), @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "blarg": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 1..9,
                    },
                    "stuff": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 9..17,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(file_parser().parse("\n[blarg]\n\n[stuff]\n"), @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "blarg": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 1..9,
                    },
                    "stuff": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 10..18,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(file_parser().parse("\n[blarg]\n  expected: PASS\n[stuff]\n"), @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "blarg": UnstructuredTest {
                        properties: {
                            "expected": Unconditional(
                                "PASS",
                            ),
                        },
                        subtests: {},
                        span: 1..26,
                    },
                    "stuff": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 26..34,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(
        file_parser().parse(r#"
[blarg]
  expected: PASS
[stuff]
"#),
        @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "blarg": UnstructuredTest {
                        properties: {
                            "expected": Unconditional(
                                "PASS",
                            ),
                        },
                        subtests: {},
                        span: 1..26,
                    },
                    "stuff": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 26..34,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(
        file_parser().parse(r#"
[blarg]
  expected: PASS
  # Below is wrong: indentation is off!
    [stuff]
      expected: TIMEOUT
"#),
        @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 66..67 expected "test section", or "file property",
        ],
    }
    "###);

    assert_debug_snapshot!(
        file_parser().parse(r#"
[blarg]
  expected: PASS
  [stuff]
    expected: TIMEOUT
"#),
        @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "blarg": UnstructuredTest {
                        properties: {
                            "expected": Unconditional(
                                "PASS",
                            ),
                        },
                        subtests: {
                            "stuff": UnstructuredSubtest {
                                properties: {
                                    "expected": Unconditional(
                                        "TIMEOUT",
                                    ),
                                },
                                span: 36..58,
                            },
                        },
                        span: 1..58,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(
        file_parser().parse(
r#"
[asdf]
  [blarg]
    expected:
      if os == "linux": FAIL
"#
        ),
        @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "asdf": UnstructuredTest {
                        properties: {},
                        subtests: {
                            "blarg": UnstructuredSubtest {
                                properties: {
                                    "expected": Conditional(
                                        ConditionalValue {
                                            conditions: [
                                                (
                                                    Eq(
                                                        Value(
                                                            Variable(
                                                                "os",
                                                            ),
                                                        ),
                                                        Value(
                                                            Literal(
                                                                String(
                                                                    "linux",
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                    "FAIL",
                                                ),
                                            ],
                                            fallback: None,
                                        },
                                    ),
                                },
                                span: 18..61,
                            },
                        },
                        span: 1..61,
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
    file_parser().parse(
r#"
[asdf]
  expected: PASS
  [blarg]
    expected: PASS
"#
    ),
    @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "asdf": UnstructuredTest {
                        properties: {
                            "expected": Unconditional(
                                "PASS",
                            ),
                        },
                        subtests: {
                            "blarg": UnstructuredSubtest {
                                properties: {
                                    "expected": Unconditional(
                                        "PASS",
                                    ),
                                },
                                span: 35..54,
                            },
                        },
                        span: 1..54,
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );

    let parser = newline().ignore_then(file_parser());

    assert_debug_snapshot!(
        parser.parse(r#"
[asdf]
  expected: PASS
"#),
    @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "asdf": UnstructuredTest {
                        properties: {
                            "expected": Unconditional(
                                "PASS",
                            ),
                        },
                        subtests: {},
                        span: 1..25,
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );
}

pub trait Tests<'a>
where
    Self: Default,
{
    type Test: Test<'a>;

    fn add_test(
        &mut self,
        name: SectionHeader,
        test: Self::Test,
        span: SimpleSpan,
        emitter: &mut Emitter<Rich<'a, char>>,
    );
}

/// A single first-level section in a [`File`].
///
/// See [`File`] for more details for the human-readable format this corresponds to.
pub trait Test<'a> {
    type Properties: Properties<'a>;
    type Subtests: Subtests<'a>;

    fn new(span: SimpleSpan, properties: Self::Properties, subtests: Self::Subtests) -> Self;
}

pub fn test_parser<'a, T>() -> impl Parser<'a, &'a str, (Option<SectionHeader>, T), ParseError<'a>>
where
    T: Test<'a>,
{
    #[derive(Debug)]
    enum Item<Tp, S> {
        Subtest {
            name: Option<SectionHeader>,
            subtest: S,
        },
        Property(Tp),
        Comment,
    }

    let items = choice((
        comment(1).map(|_comment| Item::Comment).labelled("comment"),
        subtest_parser()
            .map(|(name, subtest)| Item::Subtest { name, subtest })
            .labelled("subtest section"),
        T::Properties::property_parser(&mut PropertiesParseHelper::new(1))
            .map(Item::Property)
            .labelled("test property"),
    ))
    .padded_by(filler())
    .map_with(|item, e| (e.span(), item))
    .repeated()
    .collect::<Vec<_>>();

    let test_header = SectionHeader::parser(0)
        .then_ignore(newline().or(end()))
        .labelled("test section header");

    test_header
        .then(items)
        .validate(|(name, items), e, emitter| {
            let mut properties = T::Properties::default();
            let mut subtests = T::Subtests::default();
            for (span, item) in items {
                match item {
                    Item::Property(prop) => {
                        if let Some(prop) = prop {
                            properties.add_property(prop, emitter)
                        } else {
                            // Presumably we applied recovery and emitted an error, so skip it.
                        }
                    }
                    Item::Subtest { name, subtest } => {
                        if let Some(name) = name {
                            subtests.add_subtest(name, subtest, span, emitter)
                        } else {
                            // Presumably we applied recovery and emitted an error, so skip it.
                        }
                    }
                    Item::Comment => (),
                }
            }
            let test = T::new(e.span(), properties, subtests);
            (name, test)
        })
}

pub trait Subtests<'a>
where
    Self: Default,
{
    type Subtest: Subtest<'a>;

    fn add_subtest(
        &mut self,
        name: SectionHeader,
        subtest: Self::Subtest,
        span: SimpleSpan,
        emitter: &mut Emitter<Rich<'a, char>>,
    );
}

/// A single second-level section in a [`File`] underneath a [`Test`].
///
/// See [`File`] for more details for the human-readable format this corresponds to.
pub trait Subtest<'a> {
    type Properties: Properties<'a>;

    fn new(span: SimpleSpan, properties: Self::Properties) -> Self;
}

fn comment<'a>(indentation: u8) -> impl Parser<'a, &'a str, &'a str, ParseError<'a>> {
    group((indent(indentation), just('#'), just(' ').or_not()))
        .ignore_then(any().and_is(newline().not()).repeated().to_slice())
        .then_ignore(choice((newline(), end())))
        .labelled("comment")
}

#[test]
fn smoke_comment() {
    assert_debug_snapshot!(comment(0).parse("asdf"), @r###"
    ParseResult {
        output: None,
        errs: [
            found ''a'' at 0..1 expected ''#'',
        ],
    }
    "###);
    assert_debug_snapshot!(comment(0).parse("# asdf"), @r###"
    ParseResult {
        output: Some(
            "asdf",
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(comment(0).parse("# "), @r###"
    ParseResult {
        output: Some(
            "",
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(comment(0).parse("#"), @r###"
    ParseResult {
        output: Some(
            "",
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(
        comment(0).parse("# asdf # blarg"),
        @r###"
    ParseResult {
        output: Some(
            "asdf # blarg",
        ),
        errs: [],
    }
    "###
    );
    assert_debug_snapshot!(comment(0).parse(" # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 0..1 expected "comment",
        ],
    }
    "###);
    assert_debug_snapshot!(comment(0).parse("  # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 0..1 expected "comment",
        ],
    }
    "###);
    assert_debug_snapshot!(comment(1).parse("    # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 2..3 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(comment(1).parse("   # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 2..3 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(comment(1).parse(" # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found ''#'' at 1..2 expected "comment",
        ],
    }
    "###);
    assert_debug_snapshot!(comment(1).parse("# asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found ''#'' at 0..1 expected '' '',
        ],
    }
    "###);
    assert_debug_snapshot!(comment(2).parse("      # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 4..5 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(comment(2).parse("     # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 4..5 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(comment(2).parse("    # asdf # blarg"), @r###"
    ParseResult {
        output: Some(
            "asdf # blarg",
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(comment(2).parse("   # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found ''#'' at 3..4 expected '' '',
        ],
    }
    "###);
    assert_debug_snapshot!(comment(2).parse(" # asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found ''#'' at 1..2 expected "comment",
        ],
    }
    "###);
    assert_debug_snapshot!(comment(2).parse("# asdf # blarg"), @r###"
    ParseResult {
        output: None,
        errs: [
            found ''#'' at 0..1 expected '' '',
        ],
    }
    "###);
}

#[test]
fn smoke_test() {
    let test = UnstructuredFile::parser;

    assert_debug_snapshot!(
        test().parse("[stuff and things]\n"),
        @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "stuff and things": UnstructuredTest {
                        properties: {},
                        subtests: {},
                        span: 0..19,
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );
    assert_debug_snapshot!(
        test()
            .parse("[stuff and things]\n  expected: PASS\n"),
        @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "stuff and things": UnstructuredTest {
                        properties: {
                            "expected": Unconditional(
                                "PASS",
                            ),
                        },
                        subtests: {},
                        span: 0..36,
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );

    let test = || newline().ignore_then(test());

    assert_debug_snapshot!(
        test().parse(r#"
[stuff and things]
  expected: PASS
"#),
        @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "stuff and things": UnstructuredTest {
                        properties: {
                            "expected": Unconditional(
                                "PASS",
                            ),
                        },
                        subtests: {},
                        span: 1..37,
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        test().parse(r#"
[stuff and things]
  expected:
    if thing: boo
    yay
"#),
        @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "stuff and things": UnstructuredTest {
                        properties: {
                            "expected": Conditional(
                                ConditionalValue {
                                    conditions: [
                                        (
                                            Value(
                                                Variable(
                                                    "thing",
                                                ),
                                            ),
                                            "boo",
                                        ),
                                    ],
                                    fallback: Some(
                                        "yay",
                                    ),
                                },
                            ),
                        },
                        subtests: {},
                        span: 1..58,
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        test().parse(r#"
[cts.https.html?q=webgpu:api,operation,adapter,requestAdapter:requestAdapter_no_parameters:*]
  [:]
    expected:
      if os == "mac": FAIL


"#),
    @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {},
                tests: {
                    "cts.https.html?q=webgpu:api,operation,adapter,requestAdapter:requestAdapter_no_parameters:*": UnstructuredTest {
                        properties: {},
                        subtests: {
                            ":": UnstructuredSubtest {
                                properties: {
                                    "expected": Conditional(
                                        ConditionalValue {
                                            conditions: [
                                                (
                                                    Eq(
                                                        Value(
                                                            Variable(
                                                                "os",
                                                            ),
                                                        ),
                                                        Value(
                                                            Literal(
                                                                String(
                                                                    "mac",
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                    "FAIL",
                                                ),
                                            ],
                                            fallback: None,
                                        },
                                    ),
                                },
                                span: 101..144,
                            },
                        },
                        span: 1..144,
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );
}

pub fn subtest_parser<'a, S>(
) -> impl Parser<'a, &'a str, (Option<SectionHeader>, S), ParseError<'a>>
where
    S: Subtest<'a>,
{
    SectionHeader::parser(1)
        .then_ignore(newline().or(end()))
        .labelled("subtest section header")
        .then(
            S::Properties::property_parser(&mut PropertiesParseHelper::new(2))
                .padded_by(filler())
                .labelled("subtest property")
                .repeated()
                .collect::<Vec<_>>()
                .validate(|props, e, emitter| {
                    let mut properties = S::Properties::default();
                    for prop in props {
                        if let Some(prop) = prop {
                            properties.add_property(prop, emitter);
                        } else {
                            // An error was presumably emitted during recovery, so skip it.
                        }
                    }
                    S::new(e.span(), properties)
                }),
        )
        .labelled("subtest")
}

#[test]
fn smoke_subtest() {
    let subtest = || newline().ignore_then(subtest_parser::<UnstructuredSubtest<'_>>());

    assert_debug_snapshot!(
        subtest().parse(r#"
  [stuff and things]
"#),
        @r###"
    ParseResult {
        output: Some(
            (
                Some(
                    "stuff and things",
                ),
                UnstructuredSubtest {
                    properties: {},
                    span: 22..22,
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        subtest().parse(r#"
  [stuff and things]
    some_prop: it_works
"#),
        @r###"
    ParseResult {
        output: Some(
            (
                Some(
                    "stuff and things",
                ),
                UnstructuredSubtest {
                    properties: {
                        "some_prop": Unconditional(
                            "it_works",
                        ),
                    },
                    span: 22..46,
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        subtest().parse(r#"
  [stuff and things]
    expected:
      if thing: boo
      yay
"#),
        @r###"
    ParseResult {
        output: Some(
            (
                Some(
                    "stuff and things",
                ),
                UnstructuredSubtest {
                    properties: {
                        "expected": Conditional(
                            ConditionalValue {
                                conditions: [
                                    (
                                        Value(
                                            Variable(
                                                "thing",
                                            ),
                                        ),
                                        "boo",
                                    ),
                                ],
                                fallback: Some(
                                    "yay",
                                ),
                            },
                        ),
                    },
                    span: 22..66,
                },
            ),
        ),
        errs: [],
    }
    "###
    );
}

fn indent<'a>(level: u8) -> impl Parser<'a, &'a str, (), ParseError<'a>> {
    let level_as_space_count = usize::from(level) * 2;
    just(' ')
        .repeated()
        .exactly(level_as_space_count)
        .then_ignore(just(" ").not())
        .labelled("indentation at the proper level")
}

fn anything_at_indent_or_greater<'a>(
    level: u8,
) -> impl Clone + Parser<'a, &'a str, (), ParseError<'a>> {
    let level_as_space_count = usize::from(level) * 2;
    let indent = just(' ').repeated().exactly(level_as_space_count);
    // TODO: Figure out why this doesn't work for line-oriented content:
    //
    // ```
    // any()
    //     .and_is(newline().not())
    //     .repeated()
    //     .then(newline().or(end()))
    //     .repeated()
    //     .at_least(1)
    // ```
    custom(move |input| {
        if input.peek().is_some() {
            loop {
                let start = input.save();

                // OPT: We _might_ be able to save some cycles by looping on individual characters and
                // a finer-grained state machine.
                match input.parse(indent.ignored()) {
                    Ok(()) => {
                        input.parse(rest_of_line().ignored())?;
                        let eol = input.save();
                        match input.parse(newline()) {
                            Ok(()) => (),
                            Err(_e) => {
                                input.rewind(eol);
                                if input.next().is_none() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(_e) => {
                        input.rewind(start);
                        let offset = input.offset();
                        match input.parse(inline_whitespace().then(newline().or(end())).ignored()) {
                            Ok(()) => {
                                let made_progress = input.offset() != offset;
                                if !made_progress {
                                    break;
                                }
                            }
                            Err(_e) => {
                                input.rewind(start);
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    })
    .labelled("any content at specified indent or greater")
}

#[test]
fn anything_at_indent_or_greater_works() {
    insta::assert_debug_snapshot!(anything_at_indent_or_greater(0).parse("").into_result(), @r###"
    Ok(
        (),
    )
    "###);
    insta::assert_debug_snapshot!(anything_at_indent_or_greater(0).parse("asdf\nblarg").into_result(), @r###"
    Ok(
        (),
    )
    "###);
    insta::assert_debug_snapshot!(anything_at_indent_or_greater(0).parse("\n\n\n").into_result(), @r###"
    Ok(
        (),
    )
    "###);
    insta::assert_debug_snapshot!(anything_at_indent_or_greater(1).parse("").into_result(), @r###"
    Ok(
        (),
    )
    "###);
    insta::assert_debug_snapshot!(anything_at_indent_or_greater(1).parse("asdf\nblarg").into_result(), @r###"
    Err(
        [
            found ''a'' at 0..1 expected end of input,
        ],
    )
    "###);
    insta::assert_debug_snapshot!(anything_at_indent_or_greater(1).parse("\n\n\n").into_result(), @r###"
    Err(
        [
            found ''\n'' at 0..1 expected end of input,
        ],
    )
    "###);
}

fn rest_of_line<'a>() -> impl Clone + Parser<'a, &'a str, &'a str, ParseError<'a>> {
    any().and_is(newline().not()).repeated().to_slice()
}

#[test]
fn test_indent() {
    assert_debug_snapshot!(indent(0).parse(""), @r###"
    ParseResult {
        output: Some(
            (),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(indent(0).parse(" "), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 0..1 expected "indentation at the proper level",
        ],
    }
    "###);
    assert_debug_snapshot!(indent(0).parse("  "), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 0..1 expected "indentation at the proper level",
        ],
    }
    "###);
    assert_debug_snapshot!(indent(1).parse(""), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 0..0 expected '' '',
        ],
    }
    "###);
    assert_debug_snapshot!(indent(1).parse(" "), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 1..1 expected "indentation at the proper level",
        ],
    }
    "###);
    assert_debug_snapshot!(indent(1).parse("  "), @r###"
    ParseResult {
        output: Some(
            (),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(indent(1).parse("   "), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 2..3 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(indent(1).parse("    "), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 2..3 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(indent(2).parse(""), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 0..0 expected '' '',
        ],
    }
    "###);
    assert_debug_snapshot!(indent(2).parse(" "), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 1..1 expected "indentation at the proper level",
        ],
    }
    "###);
    assert_debug_snapshot!(indent(2).parse("  "), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 2..2 expected '' '',
        ],
    }
    "###);
    assert_debug_snapshot!(indent(2).parse("   "), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 3..3 expected '' '',
        ],
    }
    "###);
    assert_debug_snapshot!(indent(2).parse("    "), @r###"
    ParseResult {
        output: Some(
            (),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(indent(2).parse("     "), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 4..5 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(indent(2).parse("      "), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 4..5 expected something else,
        ],
    }
    "###);
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SectionHeader(pub String);

impl Debug for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(inner) = self;
        Debug::fmt(inner, f)
    }
}

impl SectionHeader {
    fn parser<'a>(indentation: u8) -> impl Parser<'a, &'a str, Option<Self>, ParseError<'a>> {
        let name = custom::<_, &str, _, _>(|input| {
            let mut escaped_name = String::new();
            loop {
                if input.parse(newline().or(end()).rewind()).is_ok() {
                    return Ok(None);
                }
                match input.peek().unwrap() {
                    ']' => break,
                    '\\' => {
                        // NOTE: keep in sync. with the escaping in `Self::escaped`!
                        let c = input.parse(just("\\]").to(']'))?;
                        escaped_name.push(c);
                    }
                    other => {
                        escaped_name.push(other);
                        input.skip();
                    }
                }
            }
            Ok(Some(escaped_name))
        })
        .validate(|escaped_name, e, emitter| {
            for (idx, c) in escaped_name
                .as_ref()
                .iter()
                .flat_map(|cs| cs.char_indices())
            {
                if c.is_control() {
                    let span_idx = e.span().start.checked_add(idx).unwrap();
                    emitter.emit(Rich::custom(
                        SimpleSpan::new(span_idx, span_idx),
                        "found illegal character in section header",
                    ));
                }
            }
            escaped_name
        });
        indent(indentation).then(just('[')).ignore_then(
            name.then_ignore(just(']'))
                .recover_with(via_parser(
                    rest_of_line().map(ToOwned::to_owned).map(|_| None),
                ))
                .map(|opt| opt.map(Self)),
        )
    }

    pub fn unescaped(&self) -> impl Display + '_ {
        let Self(inner) = self;
        inner
    }

    pub fn escaped(&self) -> impl Display + '_ {
        let Self(inner) = self;

        lazy_format!(|f| {
            let mut escaped_start = 0;
            for (idx, c) in inner.char_indices() {
                // NOTE: keep in sync. with the escaping in `Self::parser`!
                if let ']' = c {
                    write!(f, "{}\\", &inner[escaped_start..idx])?;
                    escaped_start = idx;
                }
            }
            write!(f, "{}", &inner[escaped_start..])?;
            Ok(())
        })
    }
}

#[test]
fn smoke_section_name() {
    let section_name = SectionHeader::parser;

    assert_debug_snapshot!(section_name(0).parse("hoot"), @r###"
    ParseResult {
        output: None,
        errs: [
            found ''h'' at 0..1 expected ''['',
        ],
    }
    "###);
    assert_debug_snapshot!(section_name(0).parse("[hoot]"), @r###"
    ParseResult {
        output: Some(
            Some(
                "hoot",
            ),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(section_name(0).parse("[asdf\\]blarg]"), @r###"
    ParseResult {
        output: Some(
            Some(
                "asdf]blarg",
            ),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(section_name(0).parse("[asdf]blarg]"), @r###"
    ParseResult {
        output: None,
        errs: [
            found ''b'' at 6..7 expected end of input,
        ],
    }
    "###);
}

#[test]
fn test_recover_gud_plzthx() {
    let test = newline().then(test_parser::<UnstructuredTest>());
    insta::assert_debug_snapshot!(test.parse(
        r#"
[cts.https.html?q=webgpu:api,operation,adapter,requestAdapter:requestAdapter:*]
  [:powerPreference="_undef_";forceFallbackAdapter="_undef_"]
    asdf: blarg
    expected:
      if os == "win" and debug: [PASS, FAIL]
  [:powerPreference="_undef_";forceFallbackAdapter=false]
"#), @r###"
    ParseResult {
        output: Some(
            (
                (),
                (
                    Some(
                        "cts.https.html?q=webgpu:api,operation,adapter,requestAdapter:requestAdapter:*",
                    ),
                    UnstructuredTest {
                        properties: {},
                        subtests: {
                            ":powerPreference=\"_undef_\";forceFallbackAdapter=\"_undef_\"": UnstructuredSubtest {
                                properties: {
                                    "asdf": Unconditional(
                                        "blarg",
                                    ),
                                    "expected": Conditional(
                                        ConditionalValue {
                                            conditions: [
                                                (
                                                    And(
                                                        Eq(
                                                            Value(
                                                                Variable(
                                                                    "os",
                                                                ),
                                                            ),
                                                            Value(
                                                                Literal(
                                                                    String(
                                                                        "win",
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                        Value(
                                                            Variable(
                                                                "debug",
                                                            ),
                                                        ),
                                                    ),
                                                    "[PASS, FAIL]",
                                                ),
                                            ],
                                            fallback: None,
                                        },
                                    ),
                                },
                                span: 143..218,
                            },
                            ":powerPreference=\"_undef_\";forceFallbackAdapter=false": UnstructuredSubtest {
                                properties: {},
                                span: 276..276,
                            },
                        },
                        span: 1..276,
                    },
                ),
            ),
        ),
        errs: [],
    }
    "###);
}

#[test]
fn recover_gud_plz() {
    let file_parser = newline().ignore_then(UnstructuredFile::parser());
    insta::assert_debug_snapshot!(file_parser.parse(
        r#"
readysetgameover: true
[cts.https.html?q=webgpu:api,operation,adapter,requestAdapter:requestAdapter:*]
  [:powerPreference="_undef_";forceFallbackAdapter="_undef_"]
    expected: STUPID
    wat: meh

  [:powerPreference="_undef_";forceFallbackAdapter=false]
    expected:
      if os == "win" and debug: [PASS, FAIL]

  [:powerPreference="_undef_";forceFallbackAdapter=true]
    expected:
      if os == "win" and debug: [PASS, FAIL]

[whataboutme]
  [shrug]
"#,
    ), @r###"
    ParseResult {
        output: Some(
            UnstructuredFile {
                properties: {
                    "readysetgameover": Unconditional(
                        "true",
                    ),
                },
                tests: {
                    "cts.https.html?q=webgpu:api,operation,adapter,requestAdapter:requestAdapter:*": UnstructuredTest {
                        properties: {},
                        subtests: {
                            ":powerPreference=\"_undef_\";forceFallbackAdapter=\"_undef_\"": UnstructuredSubtest {
                                properties: {
                                    "expected": Unconditional(
                                        "STUPID",
                                    ),
                                    "wat": Unconditional(
                                        "meh",
                                    ),
                                },
                                span: 166..201,
                            },
                            ":powerPreference=\"_undef_\";forceFallbackAdapter=false": UnstructuredSubtest {
                                properties: {
                                    "expected": Conditional(
                                        ConditionalValue {
                                            conditions: [
                                                (
                                                    And(
                                                        Eq(
                                                            Value(
                                                                Variable(
                                                                    "os",
                                                                ),
                                                            ),
                                                            Value(
                                                                Literal(
                                                                    String(
                                                                        "win",
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                        Value(
                                                            Variable(
                                                                "debug",
                                                            ),
                                                        ),
                                                    ),
                                                    "[PASS, FAIL]",
                                                ),
                                            ],
                                            fallback: None,
                                        },
                                    ),
                                },
                                span: 259..319,
                            },
                            ":powerPreference=\"_undef_\";forceFallbackAdapter=true": UnstructuredSubtest {
                                properties: {
                                    "expected": Conditional(
                                        ConditionalValue {
                                            conditions: [
                                                (
                                                    And(
                                                        Eq(
                                                            Value(
                                                                Variable(
                                                                    "os",
                                                                ),
                                                            ),
                                                            Value(
                                                                Literal(
                                                                    String(
                                                                        "win",
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                        Value(
                                                            Variable(
                                                                "debug",
                                                            ),
                                                        ),
                                                    ),
                                                    "[PASS, FAIL]",
                                                ),
                                            ],
                                            fallback: None,
                                        },
                                    ),
                                },
                                span: 376..436,
                            },
                        },
                        span: 24..436,
                    },
                    "whataboutme": UnstructuredTest {
                        properties: {},
                        subtests: {
                            "shrug": UnstructuredSubtest {
                                properties: {},
                                span: 460..460,
                            },
                        },
                        span: 436..460,
                    },
                },
            },
        ),
        errs: [],
    }
    "###);
}
