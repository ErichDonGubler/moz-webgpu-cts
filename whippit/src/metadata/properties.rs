pub(crate) mod conditional;
pub mod unstructured;

#[cfg(any(test, feature = "unstructured-properties"))]
pub use unstructured::UnstructuredProperties;

use std::{fmt::Debug, marker::PhantomData};

use self::conditional::unstructured_value;
pub use self::conditional::{ConditionalValue, Expr, Literal, Value};

use chumsky::{
    input::Emitter,
    prelude::Rich,
    primitive::{choice, custom, end, group, just},
    recovery::via_parser,
    text::{inline_whitespace, newline},
    Boxed, Parser,
};

use crate::metadata::{indent, ParseError};

use super::{anything_at_indent_or_greater, rest_of_line};

/// A right-hand-side property value in a [`File`], [`Test`], or [`Subtest`]. Can be
/// "unconditional"  or "conditional" (viz., runtime-evaluated). The `C` type parameter represents
/// conditional clauses. The `V` type parameter represents right-hand values that this property can
/// evaluate to.
///
/// This type is parsed using an implementation of [`Properties::property_parser`].
///
/// [`File`]: crate::metadata::File
/// [`Test`]: crate::metadata::Test
/// [`Subtest`]: crate::metadata::Subtest
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertyValue<C, V> {
    /// A property value that is only ever a specific value.
    Unconditional(V),
    /// A property value that must be computed from variables provided by an evaluator. Usually,
    /// these variables do not vary between test runs on the same machine.
    ///
    /// Upstream documentation: [`Conditional
    /// Values`](https://web-platform-tests.org/tools/wptrunner/docs/expectation.html#conditional-values)
    Conditional(ConditionalValue<C, V>),
}

impl<C, V> Default for PropertyValue<C, V>
where
    V: Default,
{
    fn default() -> Self {
        Self::Unconditional(Default::default())
    }
}

/// The core abstraction of strong property typing for [`File`]s, [`Test`]s, and [`Subtest`]s.
///
/// It is used to initialize and accumulate into the implementing data structure to represent
/// properties during parsing.
///
/// [`File`]: crate::metadata::File
/// [`Test`]: crate::metadata::Test
/// [`Subtest`]: crate::metadata::Subtest
/// [`File::parser`]: crate::metadata::File::parser
pub trait Properties<'a>
where
    Self: Clone + Default + Sized,
{
    /// The data structure that will be used to represent a single parsed property, including key,
    /// conditional expression(s), and value.
    type ParsedProperty: Clone + Debug;

    /// Retrieve a parser for a single property that [`Self::insert`] can accept.
    fn property_parser(
        helper: &mut PropertiesParseHelper<'a>,
    ) -> Boxed<'a, 'a, &'a str, Option<Self::ParsedProperty>, ParseError<'a>>;

    /// Accumulate a parsed property into this data structure.
    ///
    /// No span is provided here, but you can get one with [`chumsky::Parser::map_with`] in your
    /// implementation of [`Properties::property_parser`].
    fn add_property(&mut self, prop: Self::ParsedProperty, emitter: &mut Emitter<Rich<'a, char>>);
}

/// A helper passed to implementors of [`Properties::property_parser`]. The major affordance of
/// this API is the [`PropertiesParseHelper::parser`] API.
pub struct PropertiesParseHelper<'a> {
    indentation: u8,
    _disable_ctor: PhantomData<&'a mut ()>,
}

impl<'a> PropertiesParseHelper<'a> {
    #[cfg_attr(not(any(test, doctest)), doc(hidden))]
    pub fn new(indentation: u8) -> Self {
        Self {
            indentation,
            _disable_ctor: PhantomData,
        }
    }

    /// Create a parser for a single type of property, using the provided parsers for key,
    /// condition, and value. It is strongly recommended that you use the [`Expr`] and [`Value`]
    /// APIs to assist in parsing conditional expressions.
    ///
    /// # Examples
    ///
    /// ```
    /// use whippit::{
    ///     metadata::properties::{
    ///         ConditionalValue, Expr, Literal, PropertiesParseHelper, PropertyValue, Value
    ///     },
    ///     reexport::chumsky::{
    ///         error::Error,
    ///         prelude::*,
    ///         text::{ascii::keyword, newline},
    ///         util::MaybeRef,
    ///     }
    /// };
    ///
    /// let mut helper = PropertiesParseHelper::new(0);
    ///
    /// // Use `Expr` and `Value` parsing logic for conditionals.
    /// let my_condition_parser = Expr::parser(Value::parser());
    ///
    /// // Define a small set of properties to accept:
    /// // * `disabled`, which only ever expects a `true` RHS
    /// // * `expected`, which only ever expects a `FAIL` RHS
    /// //
    /// // If these were truly the full set of accepted values, one might want to use an `enum` and
    /// // `()` instead of retaining the `&str` values for key and value, respectively. For the
    /// // purposes of this example, though, we'll just keep things simple.
    /// let my_property_parser = helper.complete(choice((
    ///     helper.parser(
    ///         keyword("disabled"),
    ///         my_condition_parser.clone(),
    ///         keyword("true").padded(),
    ///     ),
    ///     helper.parser(
    ///         keyword("expected"),
    ///         my_condition_parser,
    ///         keyword("FAIL").padded(),
    ///     ),
    /// )));
    ///
    /// // Make multiline string examples parseable by skipping the first newline
    /// let my_property_parser = newline().ignore_then(my_property_parser);
    ///
    /// assert_eq!(
    ///     my_property_parser.parse(r#"
    /// disabled: true
    /// "#).into_result().unwrap(),
    ///     Some((
    ///         "disabled",
    ///         PropertyValue::Unconditional("true"),
    ///     )),
    /// );
    ///
    /// assert_eq!(
    ///     my_property_parser.parse(r#"
    /// expected:
    ///   if os == "win": FAIL
    /// "#).into_result().unwrap(),
    ///     Some((
    ///         "expected",
    ///         PropertyValue::Conditional(ConditionalValue {
    ///             conditions: vec![
    ///                 (
    ///                     Expr::Eq(
    ///                         Box::new(Expr::Value(
    ///                             Value::Variable("os".into())
    ///                         )),
    ///                         Box::new(Expr::Value(
    ///                             Value::Literal(Literal::String("win".into()))
    ///                         )),
    ///                     ),
    ///                     "FAIL",
    ///                 ),
    ///             ],
    ///             fallback: None,
    ///         })
    ///     )),
    /// );
    ///
    /// assert_eq!(
    ///     // Incorrect, because `BLARG` isn't the expected `FAIL`.
    ///     my_property_parser.parse(r#"
    /// expected:
    ///   if os == "win": BLARG
    /// "#).into_output_errors(),
    ///    (
    ///        Some(None),
    ///        vec![
    ///            <Rich<'_, _> as Error<'_, &'_ str>>::expected_found(
    ///                [],
    ///                None,
    ///                SimpleSpan::from(29..34)
    ///            )
    ///        ]
    ///    )
    /// );
    /// ```
    pub fn parser<K, C, V, Pk, Pc, Pv>(
        &self,
        key_ident_parser: Pk,
        condition_parser: Pc,
        value_parser: Pv,
    ) -> impl Parser<'a, &'a str, Option<(K, PropertyValue<C, V>)>, ParseError<'a>>
    where
        Pk: Clone + Parser<'a, &'a str, K, ParseError<'a>>,
        Pc: Clone + Parser<'a, &'a str, C, ParseError<'a>>,
        Pv: Clone + Parser<'a, &'a str, V, ParseError<'a>>,
        K: Clone,
        C: Clone,
        V: Clone,
    {
        let key_ident = key_ident_parser.labelled("property key");
        let condition_parser = condition_parser.labelled("conditional term for property value");
        let value_parser = value_parser.labelled("property value");

        let conditional_indent_level = self
            .indentation
            .checked_add(1)
            .expect("unexpectedly high indentation level");

        let property_value = choice((
            newline().ignore_then(
                ConditionalValue::parser(
                    conditional_indent_level,
                    condition_parser,
                    value_parser.clone(),
                )
                .recover_with(via_parser(
                    anything_at_indent_or_greater(conditional_indent_level).map(|_| None),
                ))
                .map(|opt| opt.map(PropertyValue::Conditional))
                .labelled("conditional value"),
            ),
            value_parser
                .map(Some)
                .recover_with(via_parser(unstructured_value().map(|_| None)))
                .then_ignore(newline().or(end()))
                .map(|opt| opt.map(PropertyValue::Unconditional))
                .labelled("unconditional value"),
        ))
        .labelled("property value");

        key_ident
            .then(
                Self::colon()
                    .ignore_then(property_value)
                    .recover_with(via_parser(self.recovery().map(|_| None))),
            )
            .map(|(key, value)| value.map(|value| (key, value)))
            .labelled("property")
    }

    pub fn complete<P>(
        &self,
        prop_parser: impl Parser<'a, &'a str, Option<P>, ParseError<'a>>,
    ) -> impl Parser<'a, &'a str, Option<P>, ParseError<'a>> {
        indent(self.indentation)
            .ignore_then(prop_parser.recover_with(via_parser(self.recovery().map(|_| None))))
    }

    fn colon() -> impl Clone + Parser<'a, &'a str, (), ParseError<'a>> {
        group((just(':'), inline_whitespace()))
            .ignored()
            .labelled("`: `")
    }

    fn recovery(&self) -> impl Clone + Parser<'a, &'a str, (), ParseError<'a>> {
        let conditional_indent_level = self
            .indentation
            .checked_add(1)
            .expect("unexpectedly high indentation level");

        custom(move |input| {
            let res = input.parse(rest_of_line());
            let rest_of_line = res?;
            let eol = input.parse(newline().or(end()).to_slice())?;

            if input.peek().is_none() {
                if !rest_of_line.is_empty() || !eol.is_empty() {
                    Ok(())
                } else {
                    Err(chumsky::error::Error::<'_, &str>::expected_found(
                        None,
                        None,
                        input.span_since(input.offset()),
                    ))
                }
            } else {
                input.parse(anything_at_indent_or_greater(conditional_indent_level))
            }
        })
        .ignored()
    }
}

#[test]
fn wat() {
    use chumsky::{text::ascii::keyword, IterParser};

    env_logger::init();

    let my_condition_parser = Expr::parser(Value::parser());
    let helper = PropertiesParseHelper::new(0);
    let my_property_parser = helper.complete(choice((
        helper.parser(
            keyword("disabled"),
            my_condition_parser.clone(),
            keyword("true").labelled("`true` keyword"),
        ),
        helper.parser(
            keyword("expected"),
            my_condition_parser,
            unstructured_value().labelled("test outcome"),
        ),
    )));
    insta::assert_debug_snapshot!(
        newline()
            .ignore_then(
                my_property_parser
                    .repeated()
                    .collect::<Vec<_>>()
            )
            // TODO: test empty lines, empty values, empty everything
            .parse(
                r#"
disabled: true
expected: BLARG
"#
            ),
            @r###"
    ParseResult {
        output: Some(
            [
                Some(
                    (
                        "disabled",
                        Unconditional(
                            "true",
                        ),
                    ),
                ),
                Some(
                    (
                        "expected",
                        Unconditional(
                            "BLARG",
                        ),
                    ),
                ),
            ],
        ),
        errs: [],
    }
    "###
    );
}

#[test]
fn hmm() {
    use chumsky::text;

    insta::assert_debug_snapshot!(
        text::ascii::ident::<&str, _, ParseError<'_>>()
        .try_map(|ident, span| if ident == "asdf" {
            Ok(
                ident
            )
        } else {
            Err(Rich::custom(span, format!("`{ident}` is not a valid thing-thang")))
        })
            .parse("blarg\n")
            .into_result(),

        @r###"
    Err(
        [
            `blarg` is not a valid thing-thang at 0..5,
        ],
    )
    "###

    );
}

#[test]
fn plzwork() {
    use chumsky::{prelude::*, text::keyword};

    let helper = PropertiesParseHelper::new(2);
    let my_condition_parser = Expr::parser(Value::parser());

    let my_property_parser = helper.complete(choice((
        helper.parser(
            keyword("disabled"),
            my_condition_parser.clone(),
            keyword("true").padded_by(inline_whitespace()),
        ),
        helper.parser(
            keyword("expected"),
            my_condition_parser,
            keyword("FAIL").padded_by(inline_whitespace()),
        ),
    )));

    let my_property_parser =
        newline().ignore_then(my_property_parser.repeated().collect::<Vec<_>>());

    insta::assert_debug_snapshot!(my_property_parser.parse(

        r#"
    expected: FAIL
    ofrick: lol
"#,
    ), @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 24..25 expected something else,
            found ''o'' at 24..25 expected '' '', or end of input,
        ],
    }
    "###);
}
