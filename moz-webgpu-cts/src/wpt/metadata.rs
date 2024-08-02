use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    hash::Hash,
};

use arcstr::ArcStr;
use clap::ValueEnum;
use enum_map::Enum;
use enumset::EnumSetType;
use format::lazy_format;
use joinery::JoinableIterator;
use maybe_collapsed::MaybeCollapsed;
use serde::{Deserialize, Serialize};
use strum::EnumIter;
use whippit::{
    metadata::{
        self, file_parser,
        properties::{
            ConditionalValue, Expr, Literal, Properties, PropertiesParseHelper, PropertyValue,
            Value,
        },
        ParseError, SectionHeader,
    },
    reexport::chumsky::{
        input::Emitter,
        prelude::Rich,
        primitive::{any, choice, end, group, just, one_of},
        span::SimpleSpan,
        text::{ascii, inline_whitespace, keyword, newline},
        Boxed, IterParser, Parser,
    },
};

use crate::wpt::metadata::properties::{
    DisabledString, ExpandedPropertyValue, Expected, NormalizedPropertyValue,
};

#[cfg(test)]
use insta::assert_debug_snapshot;

pub(crate) mod maybe_collapsed;
pub(crate) mod properties;

#[derive(Clone, Debug, Default, Serialize)]
pub struct File {
    pub properties: FileProps,
    pub tests: BTreeMap<SectionHeader, Test>,
}

impl File {
    pub fn parser<'a>() -> impl Parser<'a, &'a str, File, ParseError<'a>> {
        file_parser()
    }
}

impl<'a> metadata::File<'a> for File {
    type Properties = FileProps;
    type Tests = Tests;

    fn new(properties: Self::Properties, tests: Self::Tests) -> Self {
        let Tests(tests) = tests;
        Self { properties, tests }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct FileProps {
    pub disabled: Option<PropertyValue<Expr<Value<'static>>, DisabledString>>,
    #[allow(clippy::type_complexity)]
    pub prefs: Option<PropertyValue<Expr<Value<'static>>, Vec<(String, String)>>>,
    pub tags: Option<PropertyValue<Expr<Value<'static>>, Vec<String>>>,
    pub implementation_status: Option<PropertyValue<Expr<Value<'static>>, ImplementationStatus>>,
}

impl<'a> Properties<'a> for FileProps {
    type ParsedProperty = (SimpleSpan, FileProp);

    fn property_parser(
        helper: &mut PropertiesParseHelper<'a>,
    ) -> Boxed<'a, 'a, &'a str, Self::ParsedProperty, ParseError<'a>> {
        let conditional_term = Expr::parser(Value::parser().map(|expr| expr.to_static()));

        let prefs = helper
            .parser(
                just("prefs").to(()),
                conditional_term.clone(),
                group((
                    ascii::ident()
                        .or(one_of("_-").to_slice())
                        .repeated()
                        .at_least(1)
                        .separated_by(just('.'))
                        .to_slice()
                        .map(|s: &str| s.to_owned()),
                    just(':').to(()),
                    any()
                        .and_is(
                            choice((newline().to(()), end().to(()), one_of(",[]").to(()))).not(),
                        )
                        .repeated()
                        .at_least(1)
                        .to_slice()
                        .map(|s: &str| s.to_owned())
                        .labelled("pref. value"),
                ))
                .map(|(key, (), val)| (key, val))
                .separated_by(just(',').padded_by(inline_whitespace()))
                .collect()
                .delimited_by(
                    just('[').padded_by(inline_whitespace()),
                    just(']').padded_by(inline_whitespace()),
                ),
            )
            .map(|((), prefs)| FileProp::Prefs(prefs));

        let tags = helper
            .parser(
                keyword("tags").to(()),
                conditional_term.clone(),
                ascii::ident()
                    .map(|i: &str| i.to_owned())
                    .separated_by(just(',').padded_by(inline_whitespace()))
                    .collect()
                    .delimited_by(
                        just('[').padded_by(inline_whitespace()),
                        just(']').padded_by(inline_whitespace()),
                    )
                    .validate(|idents: Vec<_>, e, emitter| {
                        if idents.is_empty() {
                            emitter.emit(Rich::custom(e.span(), "no tags specified"));
                        }
                        idents
                    }),
            )
            .map(|((), tags)| FileProp::Tags(tags));

        let disabled = helper
            .parser(
                keyword(DISABLED_IDENT).to(()),
                conditional_term.clone(),
                any()
                    .and_is(newline().or(end()).not())
                    .repeated()
                    .to_slice()
                    .map(ArcStr::from)
                    .map(DisabledString::new),
            )
            .map(|((), val)| FileProp::Disabled(val));

        let implementation_status = helper
            .parser(
                ImplementationStatus::property_ident_parser(),
                conditional_term,
                ImplementationStatus::property_value_parser(),
            )
            .map(|((), implementation_status)| {
                FileProp::ImplementationStatus(implementation_status)
            });

        choice((prefs, tags, disabled, implementation_status))
            .map_with(|prop, e| (e.span(), prop))
            .boxed()
    }

    fn add_property(&mut self, prop: Self::ParsedProperty, emitter: &mut Emitter<Rich<'a, char>>) {
        let (span, prop) = prop;
        let Self {
            implementation_status,
            disabled,
            prefs,
            tags,
        } = self;
        macro_rules! check_dupe_then_insert {
            ($new:expr, $old:expr, $prop_name:expr) => {{
                if $old.replace($new).is_some() {
                    emitter.emit(Rich::custom(
                        span,
                        format!(
                            "duplicate `{}` property detected; discarding oldest",
                            $prop_name
                        ),
                    ));
                }
            }};
        }
        match prop {
            FileProp::ImplementationStatus(new_impl_status) => check_dupe_then_insert!(
                new_impl_status,
                implementation_status,
                ImplementationStatus::IDENT
            ),
            FileProp::Prefs(new_prefs) => check_dupe_then_insert!(new_prefs, prefs, "prefs"),
            FileProp::Tags(new_tags) => check_dupe_then_insert!(new_tags, tags, "tags"),
            FileProp::Disabled(new_is_disabled) => {
                check_dupe_then_insert!(new_is_disabled, disabled, DISABLED_IDENT)
            }
        }
    }
}

#[test]
fn file_props() {
    let parser = FileProps::property_parser(&mut PropertiesParseHelper::new(0));

    insta::assert_debug_snapshot!(
        parser.parse("prefs: []"),
        @r###"
    ParseResult {
        output: Some(
            (
                0..9,
                Prefs(
                    Unconditional(
                        [],
                    ),
                ),
            ),
        ),
        errs: [],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("prefs: [dom.webgpu.enabled:true]"),
        @r###"
    ParseResult {
        output: Some(
            (
                0..32,
                Prefs(
                    Unconditional(
                        [
                            (
                                "dom.webgpu.enabled",
                                "true",
                            ),
                        ],
                    ),
                ),
            ),
        ),
        errs: [],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("prefs: [dom.webgpu.enabled:[notvalidyet]]"),
        @r###"
    ParseResult {
        output: None,
        errs: [
            found ''d'' at 8..9 expected "property value",
        ],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("prefs: [dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true, dom.webgpu.testing.assert-hardware-adapter:true]"),
        @r###"
    ParseResult {
        output: Some(
            (
                0..114,
                Prefs(
                    Unconditional(
                        [
                            (
                                "dom.webgpu.enabled",
                                "true",
                            ),
                            (
                                "dom.webgpu.workers.enabled",
                                "true",
                            ),
                            (
                                "dom.webgpu.testing.assert-hardware-adapter",
                                "true",
                            ),
                        ],
                    ),
                ),
            ),
        ),
        errs: [],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("tags: []"),
        @r###"
    ParseResult {
        output: Some(
            (
                0..8,
                Tags(
                    Unconditional(
                        [],
                    ),
                ),
            ),
        ),
        errs: [
            no tags specified at 6..8,
        ],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("tags: [webgpu]"),
        @r###"
    ParseResult {
        output: Some(
            (
                0..14,
                Tags(
                    Unconditional(
                        [
                            "webgpu",
                        ],
                    ),
                ),
            ),
        ),
        errs: [],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("tags: [INVAL!D]"),
        @r###"
    ParseResult {
        output: None,
        errs: [
            found ''!'' at 12..13 expected '']'',
        ],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("implementation-status: default"),
        @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 23..24 expected "property value",
        ],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("implementation-status: implementing"),
        @r###"
    ParseResult {
        output: Some(
            (
                0..35,
                ImplementationStatus(
                    Unconditional(
                        Implementing,
                    ),
                ),
            ),
        ),
        errs: [],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("implementation-status: not-implementing"),
        @r###"
    ParseResult {
        output: Some(
            (
                0..39,
                ImplementationStatus(
                    Unconditional(
                        NotImplementing,
                    ),
                ),
            ),
        ),
        errs: [],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("implementation-status: backlog"),
        @r###"
    ParseResult {
        output: Some(
            (
                0..30,
                ImplementationStatus(
                    Unconditional(
                        Backlog,
                    ),
                ),
            ),
        ),
        errs: [],
    }
    "###
    );

    insta::assert_debug_snapshot!(
        parser.parse("implementation-status: derp"),
        @r###"
    ParseResult {
        output: None,
        errs: [
            found end of input at 23..24 expected "property value",
        ],
    }
    "###
    );

    let parser = parser.padded();

    insta::assert_debug_snapshot!(
        parser.parse(
        r###"
prefs:
  if os == "mac": [dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true, dom.webgpu.testing.assert-hardware-adapter:true]
  if os == "windows": [dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true, dom.webgpu.testing.assert-hardware-adapter:true]
  [dom.webgpu.enabled:true, dom.webgpu.workers.enabled:true]
tags: [webgpu]
disabled:
  if release_or_beta: https://mozilla-hub.atlassian.net/browse/FFXP-223
"###
    ),
    @r###"
    ParseResult {
        output: None,
        errs: [
            found ''\n'' at 324..325 expected end of input,
        ],
    }
    "###
        );
}

const DISABLED_IDENT: &str = "disabled";

#[derive(Clone, Debug)]
pub enum FileProp {
    Prefs(PropertyValue<Expr<Value<'static>>, Vec<(String, String)>>),
    Tags(PropertyValue<Expr<Value<'static>>, Vec<String>>),
    Disabled(PropertyValue<Expr<Value<'static>>, DisabledString>),
    ImplementationStatus(PropertyValue<Expr<Value<'static>>, ImplementationStatus>),
}

fn format_file_properties(props: &FileProps) -> impl Display + '_ {
    fn write_prop_val<'a, V>(
        prop_name: &'a str,
        val: &'a PropertyValue<Expr<Value>, V>,
        disp_rhs: impl Fn(&V, &mut Formatter<'_>) -> fmt::Result + 'a,
        f: &mut Formatter<'_>,
    ) -> fmt::Result {
        fn disp_condition(cond: &Expr<Value<'_>>, f: &mut Formatter<'_>) -> fmt::Result {
            match cond {
                Expr::Value(val) => match val {
                    Value::Variable(var) => write!(f, "{var}"),
                    Value::Literal(lit) => match lit {
                        Literal::String(s) => write!(f, "{s:?}"),
                    },
                },
                Expr::And(lhs, rhs) => {
                    disp_condition(lhs, f)?;
                    write!(f, " and ")?;
                    disp_condition(rhs, f)
                }
                Expr::Not(cond) => {
                    write!(f, "not ")?;
                    disp_condition(cond, f)
                }
                // TODO: almost certainly not gonna be correct with precedence rules. Eek!
                Expr::Eq(rhs, lhs) => {
                    disp_condition(rhs, f)?;
                    write!(f, " == ")?;
                    disp_condition(lhs, f)
                }
            }
        }

        write!(f, "{prop_name}:")?;
        match val {
            PropertyValue::Unconditional(val) => {
                write!(f, " ")?;
                disp_rhs(val, f)?;
                writeln!(f)?;
            }
            PropertyValue::Conditional(ConditionalValue {
                conditions,
                fallback,
            }) => {
                writeln!(f)?;
                for (condition, rhs) in conditions {
                    write!(f, "  if ")?;
                    disp_condition(condition, f)?;
                    write!(f, ": ")?;
                    disp_rhs(rhs, f)?;
                    writeln!(f)?;
                }
                if let Some(fallback) = fallback {
                    write!(f, "  ")?;
                    disp_rhs(fallback, f)?;
                    writeln!(f)?;
                }
            }
        }
        Ok(())
    }
    lazy_format!(|f| {
        let FileProps {
            implementation_status,
            disabled,
            prefs,
            tags,
        } = props;

        if let Some(implementation_status) = implementation_status {
            write_prop_val(
                ImplementationStatus::IDENT,
                implementation_status,
                Display::fmt,
                f,
            )?;
        }

        if let Some(prefs) = prefs {
            write_prop_val(
                "prefs",
                prefs,
                |prefs: &Vec<_>, f| {
                    let inner = prefs
                        .iter()
                        .map(|(key, val)| lazy_format!("{key}:{val}"))
                        .join_with(", ");
                    write!(f, "[{inner}]")
                },
                f,
            )?;
        }

        if let Some(tags) = tags {
            write_prop_val(
                "tags",
                tags,
                |tags: &Vec<_>, f| write!(f, "[{}]", tags.iter().join_with(", ")),
                f,
            )?;
        }

        if let Some(disabled) = disabled {
            write_prop_val(DISABLED_IDENT, disabled, Display::fmt, f)?;
        }

        Ok(())
    })
}

#[derive(Debug, Default, EnumSetType, Serialize, ValueEnum)]
pub enum ImplementationStatus {
    /// Indicates that functionality governing test(s) is implemented or currently being
    /// implemented, and generally expected to conform to tests.
    #[default]
    Implementing,
    /// Indicates that functionality governing test(s) is not yet implemented, but is intended to
    /// be eventually.
    Backlog,
    /// Indicates that functionality governing test(s) is not implemented, with no plans for
    /// eventual implementation.
    NotImplementing,
}

impl Display for ImplementationStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Implementing => Self::IMPLEMENTING,
                Self::Backlog => Self::BACKLOG,
                Self::NotImplementing => Self::NOT_IMPLEMENTING,
            }
        )
    }
}

impl ImplementationStatus {
    const IDENT: &'static str = "implementation-status";
    const IMPLEMENTING: &'static str = "implementing";
    const BACKLOG: &'static str = "backlog";
    const NOT_IMPLEMENTING: &'static str = "not-implementing";

    fn property_ident_parser<'a>() -> impl Parser<'a, &'a str, (), ParseError<'a>> {
        just(Self::IDENT).to(())
    }

    fn property_value_parser<'a>(
    ) -> impl Clone + Parser<'a, &'a str, ImplementationStatus, ParseError<'a>> {
        choice((
            just(Self::BACKLOG).to(ImplementationStatus::Backlog),
            just(Self::IMPLEMENTING).to(ImplementationStatus::Implementing),
            just(Self::NOT_IMPLEMENTING).to(ImplementationStatus::NotImplementing),
        ))
    }
}

#[derive(Debug, Default)]
pub struct Tests(BTreeMap<SectionHeader, Test>);

impl<'a> metadata::Tests<'a> for Tests {
    type Test = Test;

    fn add_test(
        &mut self,
        name: SectionHeader,
        test: Self::Test,
        span: SimpleSpan,
        emitter: &mut Emitter<Rich<'a, char>>,
    ) {
        let Self(tests) = self;
        if tests.get(&name).is_some() {
            emitter.emit(Rich::custom(span, "duplicate test {name:?}"));
        }
        tests.insert(name, test);
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Test {
    pub properties: TestProps<TestOutcome>,
    pub subtests: BTreeMap<SectionHeader, Subtest>,
}

#[cfg(test)]
impl Test {
    fn parser<'a>() -> impl Parser<'a, &'a str, (SectionHeader, Test), ParseError<'a>> {
        metadata::test_parser()
    }
}

impl<'a> metadata::Test<'a> for Test {
    type Properties = TestProps<TestOutcome>;
    type Subtests = Subtests;

    fn new(_span: SimpleSpan, properties: Self::Properties, subtests: Self::Subtests) -> Self {
        let Subtests(subtests) = subtests;
        Self {
            properties,
            subtests,
        }
    }
}

#[derive(Default)]
pub struct Subtests(BTreeMap<SectionHeader, Subtest>);

impl<'a> metadata::Subtests<'a> for Subtests {
    type Subtest = Subtest;

    fn add_subtest(
        &mut self,
        name: SectionHeader,
        subtest: Self::Subtest,
        span: SimpleSpan,
        emitter: &mut Emitter<Rich<'a, char>>,
    ) {
        let Self(subtests) = self;
        if subtests.get(&name).is_some() {
            emitter.emit(Rich::custom(span, "duplicate subtest {name:?}"));
        }
        subtests.insert(name, subtest);
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Subtest {
    pub properties: TestProps<SubtestOutcome>,
}

impl<'a> metadata::Subtest<'a> for Subtest {
    type Properties = TestProps<SubtestOutcome>;

    fn new(_span: SimpleSpan, properties: Self::Properties) -> Self {
        Self { properties }
    }
}

pub fn format_file(file: &File) -> impl Display + '_ {
    lazy_format!(|f| {
        let File { properties, tests } = file;
        let properties = format_file_properties(properties);
        let tests = tests
            .iter()
            .map(|(name, test)| format_test(name, test))
            .join_with("\n\n");
        write!(f, "{properties}{tests}")
    })
}

fn format_test<'a>(name: &'a SectionHeader, test: &'a Test) -> impl Display + 'a {
    lazy_format!(|f| {
        let Test {
            subtests,
            properties,
            ..
        } = test;
        write!(
            f,
            "[{}]\n{}{}",
            name.escaped(),
            format_test_properties(1, properties),
            subtests
                .iter()
                .map(|(name, subtest)| {
                    let Subtest { properties } = subtest;
                    lazy_format!(move |f| write!(
                        f,
                        "  [{}]\n{}",
                        name.escaped(),
                        format_test_properties(2, properties)
                    ))
                })
                .join_with('\n')
        )
    })
}

fn format_test_properties<Out>(indentation: u8, property: &TestProps<Out>) -> impl Display + '_
where
    Out: Default + Display + EnumSetType + Eq + PartialEq,
{
    lazy_format!(move |f| {
        let indent = lazy_format!(move |f| write!(
            f,
            "{}",
            vec![""; usize::from(indentation) + 1]
                .into_iter()
                .join_with("  ")
        ));
        let TestProps {
            disabled,
            expected,
            implementation_status,
        } = property;

        fn write_normalized<T>(
            f: &mut Formatter<'_>,
            indent: &dyn Display,
            ident: &str,
            prop: &ExpandedPropertyValue<T>,
        ) -> fmt::Result
        where
            T: Clone + Default + Display + Eq,
        {
            fn if_not_default<T>(exp: &T, f: impl FnOnce() -> fmt::Result) -> fmt::Result
            where
                T: Default + Eq,
            {
                if exp != &T::default() {
                    f()
                } else {
                    Ok(())
                }
            }

            let ident = lazy_format!("{indent}{ident}");
            let r#if = lazy_format!("{indent}  if");
            let disp_build_profile = |build_profile| match build_profile {
                BuildProfile::Debug => "debug",
                BuildProfile::Optimized => "not debug",
            };
            let normalized = NormalizedPropertyValue::from_expanded(prop.clone());
            match normalized.inner() {
                MaybeCollapsed::Collapsed(t) => match t {
                    MaybeCollapsed::Collapsed(t) => {
                        if_not_default(t, || writeln!(f, "{ident}: {t}"))?;
                    }
                    MaybeCollapsed::Expanded(by_build_profile) => {
                        writeln!(f, "{ident}:")?;
                        debug_assert!(!by_build_profile.is_empty());
                        for (build_profile, t) in by_build_profile {
                            let build_profile = disp_build_profile(*build_profile);
                            if_not_default(t, || writeln!(f, "{if} {build_profile}: {t}"))?;
                        }
                    }
                },
                MaybeCollapsed::Expanded(by_platform) => {
                    writeln!(f, "{ident}:")?;
                    debug_assert!(!by_platform.is_empty());
                    for (platform, t) in by_platform {
                        let platform = {
                            let platform_str = match platform {
                                Platform::Windows => "win",
                                Platform::Linux => "linux",
                                Platform::MacOs => "mac",
                            };
                            lazy_format!(move |f| write!(f, "os == {platform_str:?}"))
                        };
                        match t {
                            MaybeCollapsed::Collapsed(t) => {
                                if_not_default(t, || writeln!(f, "{if} {platform}: {t}"))?
                            }
                            MaybeCollapsed::Expanded(by_build_profile) => {
                                debug_assert!(!by_build_profile.is_empty());
                                for (build_profile, t) in by_build_profile {
                                    let build_profile = disp_build_profile(*build_profile);
                                    if_not_default(t, || {
                                        writeln!(f, "{if} {platform} and {build_profile}: {t}")
                                    })?;
                                }
                            }
                        }
                    }
                }
            }

            Ok(())
        }

        if let Some(implementation_status) = implementation_status {
            write_normalized(
                f,
                &indent,
                ImplementationStatus::IDENT,
                implementation_status,
            )?;
        }

        if let Some(disabled) = disabled {
            write_normalized(f, &indent, "disabled", disabled)?;
        }

        if let Some(exps) = expected {
            write_normalized(f, &indent, EXPECTED_IDENT, exps)?;
        }

        Ok(())
    })
}

#[derive(Clone, Copy, Debug, Enum, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
}

#[derive(Clone, Copy, Debug, Enum, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum BuildProfile {
    Debug,
    Optimized,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TestProps<Out>
where
    Out: EnumSetType,
{
    pub disabled: Option<ExpandedPropertyValue<DisabledString>>,
    pub expected: Option<ExpandedPropertyValue<Expected<Out>>>,
    pub implementation_status: Option<ExpandedPropertyValue<ImplementationStatus>>,
}

impl<'a, Out> TestProps<Out>
where
    Out: Clone + Default + EnumSetType + Eq + PartialEq + Hash,
{
    fn insert(&mut self, prop: TestProp<Out>, emitter: &mut Emitter<Rich<'a, char>>) {
        let Self {
            disabled,
            expected,
            implementation_status,
        } = self;

        let TestProp { kind, span } = prop;

        fn conditional<T>(
            emitter: &mut Emitter<Rich<'_, char>>,
            span: SimpleSpan,
            ident: &str,
            val: &mut Option<ExpandedPropertyValue<T>>,
            incoming: PropertyValue<Applicability, T>,
        ) where
            T: Clone + Default,
        {
            if val.is_some() {
                emitter.emit(Rich::custom(
                    span,
                    format!("duplicate `{ident}` key detected"),
                ));
                return;
            }
            val.replace(match incoming {
                PropertyValue::Unconditional(val) => ExpandedPropertyValue::unconditional(val),
                PropertyValue::Conditional(val) => {
                    let ConditionalValue {
                        conditions,
                        fallback,
                    } = val;
                    if conditions.is_empty() {
                        let fallback = fallback.unwrap_or_else(|| {
                            panic!(
                                concat!(
                                    "at least one condition or fallback not present ",
                                    "in conditional `{}` property value"
                                ),
                                ident
                            )
                        });
                        ExpandedPropertyValue::unconditional(fallback)
                    } else {
                        let fallback = fallback.unwrap_or_default();
                        ExpandedPropertyValue::from_query(|p, bp| {
                            let mut matched = None;

                            for (applicability, val) in &*conditions {
                                let Applicability {
                                    platform,
                                    build_profile,
                                } = applicability;
                                if platform.as_ref().map_or(true, |p2| *p2 == p)
                                    && build_profile.as_ref().map_or(true, |bp2| *bp2 == bp)
                                {
                                    matched = Some(val.clone());
                                }
                            }
                            matched.unwrap_or(fallback.clone())
                        })
                    }
                }
            });
        }

        match kind {
            TestPropKind::Expected(val) => {
                conditional(emitter, span, EXPECTED_IDENT, expected, val)
            }
            TestPropKind::Disabled(val) => {
                conditional(emitter, span, DISABLED_IDENT, disabled, val)
            }
            TestPropKind::ImplementationStatus(val) => conditional(
                emitter,
                span,
                ImplementationStatus::IDENT,
                implementation_status,
                val,
            ),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Applicability {
    pub platform: Option<Platform>,
    pub build_profile: Option<BuildProfile>,
}

#[derive(Clone, Debug)]
pub struct TestProp<Out>
where
    Out: EnumSetType,
{
    span: SimpleSpan,
    kind: TestPropKind<Out>,
}

#[derive(Clone, Debug)]
enum TestPropKind<Out>
where
    Out: EnumSetType,
{
    Expected(PropertyValue<Applicability, Expected<Out>>),
    Disabled(PropertyValue<Applicability, DisabledString>),
    ImplementationStatus(PropertyValue<Applicability, ImplementationStatus>),
}

impl<Out> TestProp<Out>
where
    Out: EnumSetType,
{
    fn property_parser<'a, P>(
        helper: &mut PropertiesParseHelper<'a>,
        outcome_parser: P,
    ) -> impl Parser<'a, &'a str, TestProp<Out>, ParseError<'a>>
    where
        Out: Eq + Hash + PartialEq,
        P: Clone + Parser<'a, &'a str, Out, ParseError<'a>>,
    {
        let conditional_term = Expr::parser(Value::parser()).validate(|prop_val, e, emitter| {
            let mut acc = Applicability::default();
            let try_match_var =
                |acc: &mut Applicability, val: &_, inverted: bool, emitter: &mut Emitter<_>| {
                    match val {
                        Value::Variable(var_name) if var_name == "debug" => {
                            let build_profile = if inverted {
                                BuildProfile::Optimized
                            } else {
                                BuildProfile::Debug
                            };
                            if let Some(_old) = acc.build_profile.replace(build_profile) {
                                emitter.emit(Rich::custom(
                                    e.span(),
                                    "multiple `debug` conditions specified, discarding oldest",
                                ))
                            }
                        }
                        _ => {
                            emitter.emit(Rich::custom(
                                e.span(),
                                format!(
                                    concat!(
                                        "{:?} is not a variable evaluatable with ",
                                        "tests and subtests for WebGPU's purposes, discarding"
                                    ),
                                    e.slice()
                                ),
                            ));
                        }
                    }
                };

            let try_match_eq =
                |acc: &mut Applicability, lhs: &_, rhs: &_, emitter: &mut Emitter<_>| match (
                    lhs, rhs,
                ) {
                    (
                        Expr::Value(Value::Variable(var)),
                        Expr::Value(Value::Literal(Literal::String(lit))),
                    ) if var == "os" => {
                        let platform = match &**lit {
                            "mac" => Some(Platform::MacOs),
                            "linux" => Some(Platform::Linux),
                            "win" => Some(Platform::Windows),
                            _ => None,
                        };
                        if let Some(platform) = platform {
                            if let Some(_old) = acc.platform.replace(platform) {
                                emitter.emit(Rich::custom(
                                    e.span(),
                                    "multiple `os` conditions specified, discarding oldest",
                                ))
                            }
                        } else {
                            emitter.emit(Rich::custom(
                                e.span(),
                                format!(
                                    "{lit:?}{}",
                                    concat!(
                                        " is not a platform that the WebGPU ",
                                        "team recognizes, discarding"
                                    )
                                ),
                            ))
                        }
                    }
                    _ => emitter.emit(Rich::custom(
                        e.span(),
                        format!(
                            "{:?}{}",
                            concat!(
                                " is not an comparison evaluatable ",
                                "for WebGPU's purposes, discarding"
                            ),
                            e.slice()
                        ),
                    )),
                };
            match &prop_val {
                Expr::Value(v) => try_match_var(&mut acc, v, false, emitter),
                Expr::And(lhs, rhs) => {
                    for term in [lhs, rhs] {
                        match &**term {
                            Expr::Value(v) => try_match_var(&mut acc, v, false, emitter),
                            Expr::And(_, _) => emitter.emit(Rich::custom(
                                e.span(),
                                "`and` clauses too deep here, discarding",
                            )),
                            Expr::Not(term) => match &**term {
                                Expr::Value(v) => try_match_var(&mut acc, v, true, emitter),
                                _ => emitter.emit(Rich::custom(
                                    e.span(),
                                    "conditional clause inside `not` too deep here, discarding",
                                )),
                            },
                            Expr::Eq(lhs, rhs) => try_match_eq(&mut acc, &**lhs, &**rhs, emitter),
                        }
                    }
                }
                Expr::Not(term) => match &**term {
                    Expr::Value(v) => try_match_var(&mut acc, v, true, emitter),
                    _ => emitter.emit(Rich::custom(
                        e.span(),
                        "conditional clause inside `not` too deep here, discarding",
                    )),
                },
                Expr::Eq(lhs, rhs) => try_match_eq(&mut acc, &**lhs, &**rhs, emitter),
            };
            acc
        });
        choice((
            helper
                .parser(
                    just(EXPECTED_IDENT).to(()),
                    conditional_term.clone(),
                    choice((
                        outcome_parser.clone().map(Expected::permanent),
                        outcome_parser
                            .padded_by(inline_whitespace())
                            .separated_by(just(','))
                            .collect::<Vec<_>>()
                            .map(|vec| vec.into_iter().collect())
                            .delimited_by(just('['), just(']'))
                            .try_map(|outcomes, span| {
                                Expected::intermittent(outcomes).ok_or_else(|| {
                                    Rich::custom(
                                        span,
                                        "intermittent outcomes must have at least 2 elements",
                                    )
                                })
                            }),
                    ))
                    .padded_by(inline_whitespace()),
                )
                .map_with(|((), val), e| TestProp {
                    span: e.span(),
                    kind: TestPropKind::Expected(val),
                }),
            helper
                .parser(
                    just(DISABLED_IDENT).to(()),
                    conditional_term.clone(),
                    any()
                        .and_is(newline().not())
                        .repeated()
                        .to_slice()
                        .map(ArcStr::from)
                        .map(DisabledString::new),
                )
                .map_with(|((), val), e| TestProp {
                    span: e.span(),
                    kind: TestPropKind::Disabled(val),
                }),
            helper
                .parser(
                    ImplementationStatus::property_ident_parser(),
                    conditional_term,
                    ImplementationStatus::property_value_parser(),
                )
                .map_with(|((), val), e| TestProp {
                    span: e.span(),
                    kind: TestPropKind::ImplementationStatus(val),
                }),
        ))
    }
}

pub(crate) const EXPECTED_IDENT: &str = "expected";
pub(crate) const PASS: &str = "PASS";
pub(crate) const FAIL: &str = "FAIL";
pub(crate) const NOTRUN: &str = "NOTRUN";
pub(crate) const TIMEOUT: &str = "TIMEOUT";
pub(crate) const SKIP: &str = "SKIP";
pub(crate) const CRASH: &str = "CRASH";
pub(crate) const OK: &str = "OK";
pub(crate) const ERROR: &str = "ERROR";

#[derive(Debug, Deserialize, EnumSetType, Hash, Serialize)]
#[enumset(serialize_repr = "list")]
#[enumset(serialize_deny_unknown)]
#[serde(rename_all = "UPPERCASE")]
pub enum TestOutcome {
    Ok,
    Pass,
    Fail,
    Timeout,
    Crash,
    Error,
    Skip,
}

impl Default for TestOutcome {
    fn default() -> Self {
        Self::Ok
    }
}

impl Display for TestOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Ok => OK,
                Self::Pass => PASS,
                Self::Fail => FAIL,
                Self::Timeout => TIMEOUT,
                Self::Crash => CRASH,
                Self::Error => ERROR,
                Self::Skip => SKIP,
            }
        )
    }
}

impl<'a> Properties<'a> for TestProps<TestOutcome> {
    type ParsedProperty = TestProp<TestOutcome>;
    fn property_parser(
        helper: &mut PropertiesParseHelper<'a>,
    ) -> Boxed<'a, 'a, &'a str, Self::ParsedProperty, ParseError<'a>> {
        TestProp::property_parser(
            helper,
            choice((
                keyword(OK).to(TestOutcome::Ok),
                keyword(PASS).to(TestOutcome::Pass),
                keyword(FAIL).to(TestOutcome::Fail),
                keyword(CRASH).to(TestOutcome::Crash),
                keyword(TIMEOUT).to(TestOutcome::Timeout),
                keyword(ERROR).to(TestOutcome::Error),
                keyword(SKIP).to(TestOutcome::Skip),
            )),
        )
        .boxed()
    }

    fn add_property(&mut self, prop: Self::ParsedProperty, emitter: &mut Emitter<Rich<'a, char>>) {
        self.insert(prop, emitter)
    }
}

#[derive(Debug, Deserialize, EnumSetType, Hash, Serialize)]
#[enumset(serialize_repr = "list")]
#[enumset(serialize_deny_unknown)]
#[serde(rename_all = "UPPERCASE")]
pub enum SubtestOutcome {
    Pass,
    Fail,
    Timeout,
    Crash,
    NotRun,
}

impl Default for SubtestOutcome {
    fn default() -> Self {
        Self::Pass
    }
}

impl Display for SubtestOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Pass => PASS,
                Self::Fail => FAIL,
                Self::Timeout => TIMEOUT,
                Self::Crash => CRASH,
                Self::NotRun => NOTRUN,
            }
        )
    }
}

impl<'a> Properties<'a> for TestProps<SubtestOutcome> {
    type ParsedProperty = TestProp<SubtestOutcome>;
    fn property_parser(
        helper: &mut PropertiesParseHelper<'a>,
    ) -> Boxed<'a, 'a, &'a str, Self::ParsedProperty, ParseError<'a>> {
        TestProp::property_parser(
            helper,
            choice((
                keyword(PASS).to(SubtestOutcome::Pass),
                keyword(FAIL).to(SubtestOutcome::Fail),
                keyword(TIMEOUT).to(SubtestOutcome::Timeout),
                keyword(CRASH).to(SubtestOutcome::Crash),
                keyword(NOTRUN).to(SubtestOutcome::NotRun),
            )),
        )
        .boxed()
    }

    fn add_property(&mut self, prop: Self::ParsedProperty, emitter: &mut Emitter<Rich<'a, char>>) {
        self.insert(prop, emitter)
    }
}

#[cfg(test)]
fn single_leading_newline<'a, T, Pt>(p: Pt) -> impl Parser<'a, &'a str, T, ParseError<'a>>
where
    Pt: Parser<'a, &'a str, T, ParseError<'a>>,
{
    newline().ignore_then(p)
}

#[test]
fn test_sample_exps() {
    let parser = || newline().ignore_then(File::parser());

    assert_debug_snapshot!(
        parser().parse(
r#"
[asdf]
"#
        ),
        @r###"
    ParseResult {
        output: Some(
            File {
                properties: FileProps {
                    is_disabled: None,
                    prefs: None,
                    tags: None,
                    implementation_status: None,
                },
                tests: {
                    "asdf": Test {
                        properties: TestProps {
                            is_disabled: false,
                            expected: None,
                            implementation_status: None,
                        },
                        subtests: {},
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        parser().parse(
r#"
[asdf]
  [blarg]
"#
        ),
        @r###"
    ParseResult {
        output: Some(
            File {
                properties: FileProps {
                    is_disabled: None,
                    prefs: None,
                    tags: None,
                    implementation_status: None,
                },
                tests: {
                    "asdf": Test {
                        properties: TestProps {
                            is_disabled: false,
                            expected: None,
                            implementation_status: None,
                        },
                        subtests: {
                            "blarg": Subtest {
                                properties: TestProps {
                                    is_disabled: false,
                                    expected: None,
                                    implementation_status: None,
                                },
                            },
                        },
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        parser().parse(
r#"
[asdf]
  [blarg]
    expected: PASS
"#
        ),
        @r###"
    ParseResult {
        output: Some(
            File {
                properties: FileProps {
                    is_disabled: None,
                    prefs: None,
                    tags: None,
                    implementation_status: None,
                },
                tests: {
                    "asdf": Test {
                        properties: TestProps {
                            is_disabled: false,
                            expected: None,
                            implementation_status: None,
                        },
                        subtests: {
                            "blarg": Subtest {
                                properties: TestProps {
                                    is_disabled: false,
                                    expected: Some(
                                        ExpandedPropertyValue(
                                            {
                                                Windows: {
                                                    Debug: [
                                                        Pass,
                                                    ],
                                                    Optimized: [
                                                        Pass,
                                                    ],
                                                },
                                                Linux: {
                                                    Debug: [
                                                        Pass,
                                                    ],
                                                    Optimized: [
                                                        Pass,
                                                    ],
                                                },
                                                MacOs: {
                                                    Debug: [
                                                        Pass,
                                                    ],
                                                    Optimized: [
                                                        Pass,
                                                    ],
                                                },
                                            },
                                        ),
                                    ),
                                    implementation_status: None,
                                },
                            },
                        },
                    },
                },
            },
        ),
        errs: [],
    }
    "###
    );

    let parser = || single_leading_newline(Test::parser());

    assert_debug_snapshot!(
        parser().parse(
r#"
[asdf]
  [blarg]
    expected: [PASS, FAIL]
"#
        ),
        @r###"
    ParseResult {
        output: Some(
            (
                "asdf",
                Test {
                    properties: TestProps {
                        is_disabled: false,
                        expected: None,
                        implementation_status: None,
                    },
                    subtests: {
                        "blarg": Subtest {
                            properties: TestProps {
                                is_disabled: false,
                                expected: Some(
                                    ExpandedPropertyValue(
                                        {
                                            Windows: {
                                                Debug: [
                                                    Pass,
                                                    Fail,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                    Fail,
                                                ],
                                            },
                                            Linux: {
                                                Debug: [
                                                    Pass,
                                                    Fail,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                    Fail,
                                                ],
                                            },
                                            MacOs: {
                                                Debug: [
                                                    Pass,
                                                    Fail,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                    Fail,
                                                ],
                                            },
                                        },
                                    ),
                                ),
                                implementation_status: None,
                            },
                        },
                    },
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        parser().parse(
r#"
[asdf]
  expected: OK
  [blarg]
    expected: PASS
"#
        ),
        @r###"
    ParseResult {
        output: Some(
            (
                "asdf",
                Test {
                    properties: TestProps {
                        is_disabled: false,
                        expected: Some(
                            ExpandedPropertyValue(
                                {
                                    Windows: {
                                        Debug: [
                                            Ok,
                                        ],
                                        Optimized: [
                                            Ok,
                                        ],
                                    },
                                    Linux: {
                                        Debug: [
                                            Ok,
                                        ],
                                        Optimized: [
                                            Ok,
                                        ],
                                    },
                                    MacOs: {
                                        Debug: [
                                            Ok,
                                        ],
                                        Optimized: [
                                            Ok,
                                        ],
                                    },
                                },
                            ),
                        ),
                        implementation_status: None,
                    },
                    subtests: {
                        "blarg": Subtest {
                            properties: TestProps {
                                is_disabled: false,
                                expected: Some(
                                    ExpandedPropertyValue(
                                        {
                                            Windows: {
                                                Debug: [
                                                    Pass,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                ],
                                            },
                                            Linux: {
                                                Debug: [
                                                    Pass,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                ],
                                            },
                                            MacOs: {
                                                Debug: [
                                                    Pass,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                ],
                                            },
                                        },
                                    ),
                                ),
                                implementation_status: None,
                            },
                        },
                    },
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        parser().parse(
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
            (
                "asdf",
                Test {
                    properties: TestProps {
                        is_disabled: false,
                        expected: None,
                        implementation_status: None,
                    },
                    subtests: {
                        "blarg": Subtest {
                            properties: TestProps {
                                is_disabled: false,
                                expected: Some(
                                    ExpandedPropertyValue(
                                        {
                                            Windows: {
                                                Debug: [
                                                    Pass,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                ],
                                            },
                                            Linux: {
                                                Debug: [
                                                    Fail,
                                                ],
                                                Optimized: [
                                                    Fail,
                                                ],
                                            },
                                            MacOs: {
                                                Debug: [
                                                    Pass,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                ],
                                            },
                                        },
                                    ),
                                ),
                                implementation_status: None,
                            },
                        },
                    },
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        parser().parse(
r#"
[asdf]
  [blarg]
    expected:
      if os == "linux": FAIL
      TIMEOUT
"#
        ),
        @r###"
    ParseResult {
        output: Some(
            (
                "asdf",
                Test {
                    properties: TestProps {
                        is_disabled: false,
                        expected: None,
                        implementation_status: None,
                    },
                    subtests: {
                        "blarg": Subtest {
                            properties: TestProps {
                                is_disabled: false,
                                expected: Some(
                                    ExpandedPropertyValue(
                                        {
                                            Windows: {
                                                Debug: [
                                                    Timeout,
                                                ],
                                                Optimized: [
                                                    Timeout,
                                                ],
                                            },
                                            Linux: {
                                                Debug: [
                                                    Fail,
                                                ],
                                                Optimized: [
                                                    Fail,
                                                ],
                                            },
                                            MacOs: {
                                                Debug: [
                                                    Timeout,
                                                ],
                                                Optimized: [
                                                    Timeout,
                                                ],
                                            },
                                        },
                                    ),
                                ),
                                implementation_status: None,
                            },
                        },
                    },
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        parser().parse(r#"
[cts.https.html?q=webgpu:api,validation,buffer,destroy:twice:*]
  [:]
    expected:
      if os == "mac": FAIL

"#),
    @r###"
    ParseResult {
        output: Some(
            (
                "cts.https.html?q=webgpu:api,validation,buffer,destroy:twice:*",
                Test {
                    properties: TestProps {
                        is_disabled: false,
                        expected: None,
                        implementation_status: None,
                    },
                    subtests: {
                        ":": Subtest {
                            properties: TestProps {
                                is_disabled: false,
                                expected: Some(
                                    ExpandedPropertyValue(
                                        {
                                            Windows: {
                                                Debug: [
                                                    Pass,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                ],
                                            },
                                            Linux: {
                                                Debug: [
                                                    Pass,
                                                ],
                                                Optimized: [
                                                    Pass,
                                                ],
                                            },
                                            MacOs: {
                                                Debug: [
                                                    Fail,
                                                ],
                                                Optimized: [
                                                    Fail,
                                                ],
                                            },
                                        },
                                    ),
                                ),
                                implementation_status: None,
                            },
                        },
                    },
                },
            ),
        ),
        errs: [],
    }
    "###
    );

    assert_debug_snapshot!(
        parser().parse(
r#"
[canvas_complex_rgba8unorm_store.https.html]
  expected: [PASS, FAIL]
"#
        ),
        @r###"
    ParseResult {
        output: Some(
            (
                "canvas_complex_rgba8unorm_store.https.html",
                Test {
                    properties: TestProps {
                        is_disabled: false,
                        expected: Some(
                            ExpandedPropertyValue(
                                {
                                    Windows: {
                                        Debug: [
                                            Pass,
                                            Fail,
                                        ],
                                        Optimized: [
                                            Pass,
                                            Fail,
                                        ],
                                    },
                                    Linux: {
                                        Debug: [
                                            Pass,
                                            Fail,
                                        ],
                                        Optimized: [
                                            Pass,
                                            Fail,
                                        ],
                                    },
                                    MacOs: {
                                        Debug: [
                                            Pass,
                                            Fail,
                                        ],
                                        Optimized: [
                                            Pass,
                                            Fail,
                                        ],
                                    },
                                },
                            ),
                        ),
                        implementation_status: None,
                    },
                    subtests: {},
                },
            ),
        ),
        errs: [],
    }
    "###
    );
}
