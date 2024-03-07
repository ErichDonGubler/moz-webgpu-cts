//! Data structures representing conditional expressions in [WPT metadata properties](super).

pub(crate) mod expr;

#[cfg(test)]
use {
    crate::metadata::properties::unstructured::unstructured_conditional_term,
    insta::assert_debug_snapshot,
};

use std::convert::identity;

use chumsky::{
    prelude::Rich,
    primitive::{any, custom, end, group, just},
    recovery::via_parser,
    text::{ascii::keyword, newline},
    IterParser, Parser,
};

use crate::metadata::{indent, rest_of_line, ParseError};

pub use self::expr::{Expr, Literal, Value};

/// TODO: document recovery and errors
fn conditional_rule<'a, C, V, Pc, Pv>(
    indentation: u8,
    condition_parser: Pc,
    value_parser: Pv,
) -> impl Parser<'a, &'a str, Option<(C, V)>, ParseError<'a>>
where
    Pc: Parser<'a, &'a str, C, ParseError<'a>>,
    Pv: Parser<'a, &'a str, V, ParseError<'a>>,
{
    group((
        indent(indentation),
        keyword("if").labelled("`if` keyword"),
        just(' ').labelled("space"),
    ))
    .ignore_then(
        condition_parser
            .then_ignore(group((just(':').to(()), just(' ').or_not().to(()))))
            .then(value_parser)
            .then_ignore(newline().or(end()))
            .map(Some)
            .recover_with(via_parser(
                custom(|input| {
                    if input.peek().is_none() {
                        Err(chumsky::error::Error::<'_, &str>::expected_found(
                            None,
                            None,
                            input.span_since(input.offset()),
                        ))
                    } else {
                        Ok(())
                    }
                })
                .ignore_then(rest_of_line().then(newline().or(end())).map(|_| None)),
            )),
    )
    .labelled("conditional value rule")
}

#[test]
fn test_conditional_rule() {
    let conditional_rule = |indent| {
        conditional_rule(
            indent,
            unstructured_conditional_term(),
            unstructured_value(),
        )
    };

    assert_debug_snapshot!(conditional_rule(0).parse("if os == \"sux\": woot"), @r###"
    ParseResult {
        output: Some(
            Some(
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
                                    "sux",
                                ),
                            ),
                        ),
                    ),
                    "woot",
                ),
            ),
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(conditional_rule(1).parse("  if os == \"sux\": woot"), @r###"
    ParseResult {
        output: Some(
            Some(
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
                                    "sux",
                                ),
                            ),
                        ),
                    ),
                    "woot",
                ),
            ),
        ),
        errs: [],
    }
    "###);

    let conditional_rule = |indent| newline().ignore_then(conditional_rule(indent));

    assert_debug_snapshot!(
        conditional_rule(1).parse(r#"
  if os == "sux": woot
"#),
    @r###"
    ParseResult {
        output: Some(
            Some(
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
                                    "sux",
                                ),
                            ),
                        ),
                    ),
                    "woot",
                ),
            ),
        ),
        errs: [],
    }
    "###);

    assert_debug_snapshot!(
        conditional_rule(1).parse(r#"
  if debug: ohnoes
"#),
    @r###"
    ParseResult {
        output: Some(
            Some(
                (
                    Value(
                        Variable(
                            "debug",
                        ),
                    ),
                    "ohnoes",
                ),
            ),
        ),
        errs: [],
    }
    "###);
}

fn conditional_fallback<'a, V, Pv>(
    indentation: u8,
    value_parser: Pv,
) -> impl Parser<'a, &'a str, Option<V>, ParseError<'a>>
where
    Pv: Parser<'a, &'a str, V, ParseError<'a>>,
{
    indent(indentation)
        .ignore_then(
            value_parser
                .map(Some)
                .recover_with(via_parser(unstructured_value().map(|_| None))),
        )
        .then_ignore(newline().or(end()))
        .labelled("conditional value fallback")
}

#[test]
fn test_conditional_fallback() {
    let conditional_fallback = |indent| conditional_fallback(indent, unstructured_value());

    assert_debug_snapshot!(conditional_fallback(0).parse("[PASS, FAIL]"), @r###"
    ParseResult {
        output: Some(
            Some(
                "[PASS, FAIL]",
            ),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(0).parse(r#""okgo""#), @r###"
    ParseResult {
        output: Some(
            Some(
                "\"okgo\"",
            ),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(0).parse(""), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 0..0 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(1).parse(""), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 0..0 expected '' '',
        ],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(1).parse("  "), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 2..2 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(1).parse("  @False"), @r###"
    ParseResult {
        output: Some(
            Some(
                "@False",
            ),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(1).parse("    @False"), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 2..3 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(3).parse(""), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 0..0 expected '' '',
        ],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(3).parse("      "), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 6..6 expected something else,
        ],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(3).parse("      @True"), @r###"
    ParseResult {
        output: Some(
            Some(
                "@True",
            ),
        ),
        errs: [],
    }
    "###);
    assert_debug_snapshot!(conditional_fallback(3).parse("        @True"), @r###"
    ParseResult {
        output: None,
        errs: [
            found '' '' at 6..7 expected something else,
        ],
    }
    "###);
}

/// Values placed into a [`super::PropertyValue::Conditional`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalValue<C, V> {
    /// Conditional clauses and their resulting values if evaluated to true.
    pub conditions: Vec<(C, V)>,
    /// The value applied if no `conditions` apply.
    pub fallback: Option<V>,
}

impl<C, V> Default for ConditionalValue<C, V> {
    fn default() -> Self {
        Self {
            conditions: Default::default(),
            fallback: Default::default(),
        }
    }
}

impl<C, V> ConditionalValue<C, V> {
    pub(super) fn parser<'a, Pc, Pv>(
        indentation: u8,
        condition_parser: Pc,
        value_parser: Pv,
    ) -> impl Parser<'a, &'a str, Option<ConditionalValue<C, V>>, ParseError<'a>>
    where
        Pc: Parser<'a, &'a str, C, ParseError<'a>>,
        Pv: Clone + Parser<'a, &'a str, V, ParseError<'a>>,
    {
        conditional_rule(indentation, condition_parser, value_parser.clone())
            .repeated()
            .at_least(1)
            .collect::<Vec<_>>()
            .then(conditional_fallback(indentation, value_parser).or_not())
            .validate(|(conditions, fallback), e, emitter| {
                if conditions.is_empty() && fallback.is_none() {
                    emitter.emit(Rich::custom(
                        e.span(),
                        concat!(
                            "this conditional property value has no conditional ",
                            "rules or fallback specified",
                        ),
                    ));
                }
                let conditions = conditions
                    .into_iter()
                    .filter_map(identity)
                    .collect::<Vec<_>>();
                if conditions.is_empty() && fallback.is_none() {
                    None
                } else {
                    Some(ConditionalValue {
                        conditions,
                        fallback: fallback.flatten(),
                    })
                }
            })
            .labelled("conditional value")
    }
}

pub(crate) fn unstructured_value<'a>() -> impl Clone + Parser<'a, &'a str, &'a str, ParseError<'a>>
{
    any()
        .and_is(newline().not())
        .repeated()
        .at_least(1)
        .to_slice()
}

#[test]
fn test_conditional_value() {
    let conditional_value = |indent| {
        ConditionalValue::parser(
            indent,
            unstructured_conditional_term(),
            unstructured_value(),
        )
    };

    assert_debug_snapshot!(
        // Should fail, no conditional rules.
        conditional_value(0).parse("TIMEOUT"),
        @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 0..7 expected something else,
        ],
    }
    "###
    );

    assert_debug_snapshot!(
        conditional_value(0).parse("if os == \"awesome\": great"),
        @r###"
    ParseResult {
        output: Some(
            Some(
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
                                            "awesome",
                                        ),
                                    ),
                                ),
                            ),
                            "great",
                        ),
                    ],
                    fallback: None,
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    let conditional_value = |indent| newline().ignore_then(conditional_value(indent));

    assert_debug_snapshot!(
        conditional_value(0).parse(r#"
if os == "mac": PASS
if os == "linux": FAIL
TIMEOUT
"#),
        @r###"
    ParseResult {
        output: Some(
            Some(
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
                            "PASS",
                        ),
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
                    fallback: Some(
                        "TIMEOUT",
                    ),
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        conditional_value(0).parse(r#"
if os == "mac": PASS
"#),
        @r###"
    ParseResult {
        output: Some(
            Some(
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
                            "PASS",
                        ),
                    ],
                    fallback: None,
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        conditional_value(0).parse(r#"
if os == "mac": PASS
if os == "linux": FAIL
"#),
        @r###"
    ParseResult {
        output: Some(
            Some(
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
                            "PASS",
                        ),
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
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        conditional_value(1).parse(r#"
  if os == "mac": PASS
  if os == "linux": FAIL
"#),
        @r###"
    ParseResult {
        output: Some(
            Some(
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
                            "PASS",
                        ),
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
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        conditional_value(1).parse(r#"
  if os == "mac": PASS
  if os == "linux": FAIL
  TIMEOUT
"#),
        @r###"
    ParseResult {
        output: Some(
            Some(
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
                            "PASS",
                        ),
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
                    fallback: Some(
                        "TIMEOUT",
                    ),
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        conditional_value(1).parse(r#"
  if os == "mac": [dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true, dom.webgpu.testing.assert-hardware-adapter:true]
  if os == "windows": [dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true, dom.webgpu.testing.assert-hardware-adapter:true]
  [dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true]
"#),
        @r###"
    ParseResult {
        output: Some(
            Some(
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
                            "[dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true, dom.webgpu.testing.assert-hardware-adapter:true]",
                        ),
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
                                            "windows",
                                        ),
                                    ),
                                ),
                            ),
                            "[dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true, dom.webgpu.testing.assert-hardware-adapter:true]",
                        ),
                    ],
                    fallback: Some(
                        "[dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true]",
                    ),
                },
            ),
        ),
        errs: [],
    }
    "###
    );
}
