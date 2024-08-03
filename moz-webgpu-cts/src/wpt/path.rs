use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    path::Path,
};

use camino::{Utf8Component, Utf8Path};
use clap::ValueEnum;
use format::lazy_format;
use itertools::Itertools;
use joinery::JoinableIterator;
use strum::{EnumIter, IntoEnumIterator};

/// A browser supported by [crate::main], used for [`TestEntryPath`]s.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ValueEnum)]
pub(crate) enum Browser {
    Firefox,
    Servo,
}

impl Browser {
    /// NOTE: Keep this implementation in sync with [`RootDir::url_prefix`].
    pub(crate) fn strip_wpt_url_prefix<'a>(&self, url_path: &'a str) -> Option<(RootDir, &'a str)> {
        let strip_prefix = |prefix, root_dir| {
            url_path
                .strip_prefix(prefix)
                .map(|stripped| (root_dir, stripped))
        };
        match self {
            Browser::Firefox => strip_prefix("/_mozilla/", FirefoxRootDir::Mozilla.into())
                .or_else(|| strip_prefix("/", FirefoxRootDir::Upstream.into())),
            Browser::Servo => strip_prefix("/_webgpu/", ServoRootDir::WebGpu.into()),
        }
    }

    /// NOTE: Keep this implementation in sync with [`RootDir::components`].
    pub(crate) fn strip_wpt_root_dir_prefix<'a>(
        &self,
        path: &'a Utf8Path,
    ) -> Result<(RootDir, &'a Utf8Path), std::path::StripPrefixError> {
        let strip_prefix = |prefix, root_dir| {
            path.strip_prefix(prefix)
                .map(|stripped| (root_dir, stripped))
        };
        match self {
            Browser::Firefox => {
                strip_prefix(ROOT_DIR_FX_MOZILLA_STR, FirefoxRootDir::Mozilla.into()).or_else(
                    |_| strip_prefix(ROOT_DIR_FX_UPSTREAM_STR, FirefoxRootDir::Upstream.into()),
                )
            }
            Browser::Servo => strip_prefix(ROOT_DIR_SERVO_WEBGPU_STR, ServoRootDir::WebGpu.into()),
        }
    }
}

/// A symbolic path to a WPT test specification, which may contain one or more executed test
/// entries (see also [`TestEntry`]). Includes methods for rendering paths to test and metadata
/// files.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SpecPath<'a> {
    pub root_dir: RootDir,
    /// A relative offset into `root_dir`.
    pub path: Cow<'a, Utf8Path>,
    pub r#type: SpecType,
}

/// The type of tests that can be specified in a [`SpecPath`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum SpecType {
    /// A JavaScript test.
    ///
    /// See also:
    ///
    /// * [WPT upstream docs.' "JavaScript Tests (`testharness.js`)" section][upstream] for
    ///   background.
    /// * [`JsExecScope`], which will be set in test entries specified in a file with this type.
    ///
    /// [upstream]: https://web-platform-tests.org/writing-tests/testharness.html
    Js(JsSpecType),
    /// A catch-all for all `*.html` test spec. files. This is likely incorrect, but it works well
    /// enough for now!
    Html,
    // NOTE: Other types exist, but we haven't been forced to support them yet. 🙂
}

impl SpecType {
    fn iter() -> impl Iterator<Item = Self> {
        [Self::Html, Self::Js(JsSpecType::DedicatedWorker)].into_iter()
    }

    pub fn from_base_name(base_name: &str) -> Option<(Self, &str)> {
        Self::iter().find_map(|variant| {
            strip_suffix_with_value(base_name, variant.file_extension(), variant)
        })
    }

    pub fn validate_test_entry_base_name<'a>(
        &self,
        base_name: &'a str,
    ) -> Option<(TestEntryType, &'a str)> {
        let permitted_test_entry_types = match self {
            Self::Js(JsSpecType::DedicatedWorker) => &[TestEntryType::Js {
                exec_scope: JsExecScope::DedicatedWorker,
            }],
            Self::Html => &[TestEntryType::Html],
        };
        permitted_test_entry_types
            .iter()
            .copied()
            .find_map(|test_entry_type| {
                strip_suffix_with_value(
                    base_name,
                    test_entry_type.file_extension(),
                    test_entry_type,
                )
            })
    }

    pub fn file_extension(&self) -> &'static str {
        match self {
            SpecType::Js(JsSpecType::DedicatedWorker) => ".worker.js",
            SpecType::Html => ".html",
        }
    }
}

/// A subtype of [`SpecType::Js`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum JsSpecType {
    /// A `*.worker.js` test.
    DedicatedWorker,
}

/// A symbolic path to an executed WPT test entry and its metadata, contained in a test
/// specification (see also [`SpecPath`]). In combination with [`SpecPath`], this is useful for
/// correlating entries from [`ExecutionReport`]s and [`metadata::File`]s.
///
/// [`ExecutionReport`]: crate::report::ExecutionReport
/// [`metadata::File`]: crate::wpt::metadata::File
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TestEntry<'a> {
    /// The type of this entry. Based on it's spec. file's type (see [`SpecPath::type`]).
    pub r#type: TestEntryType,
    /// The variant of this particular test from this test's source code. If set, you should be
    /// able to correlate this with
    ///
    /// Generally, a test in WPT is _either_ a single test, or a set of test variants. That is, for
    /// a given `path`, there will be a single `variant: None`, or multiple tests with `variant:
    /// Some(…)`.
    pub variant: Option<Cow<'a, str>>,
}

/// The test entry analogue to [`SpecPath::type`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TestEntryType {
    /// An HTML-authored test with no divergence from the base name of its corresponding spec.
    /// file. Corresponds to [`SpecType::Html`].
    Html,
    /// Corresponds to [`SpecType::Js`]. The test entry will have slightly different naming from
    /// its spec. file.
    ///
    /// JS tests are converted to `*.html` tests at test execution time and reported as such.
    /// The set of values observable here are determined by this entry's spec.'s
    /// [`SpecPath::type`] and its
    ///
    /// See also [WPT upstream's docs.' "Test Features" section][upstream]
    ///
    /// [upstream]: https://web-platform-tests.org/writing-tests/file-names.html#test-features
    Js { exec_scope: JsExecScope },
}

impl TestEntryType {
    fn iter() -> impl Iterator<Item = Self> {
        // NOTE: `Html`'s file extension is less specific than other file extensions, so try
        // matching it last.
        JsExecScope::iter()
            .map(|exec_scope| Self::Js { exec_scope })
            .chain([Self::Html])
    }

    pub fn from_base_name(base_name: &str) -> Option<(Self, &str)> {
        Self::iter().find_map(|variant| {
            strip_suffix_with_value(base_name, variant.file_extension(), variant)
        })
    }

    pub fn file_extension(self) -> &'static str {
        match self {
            Self::Html => ".html",
            Self::Js { exec_scope } => match exec_scope {
                JsExecScope::DedicatedWorker => ".worker.html",
            },
        }
    }

    pub fn spec_type(self) -> SpecType {
        match self {
            Self::Html => SpecType::Html,
            Self::Js { exec_scope } => match exec_scope {
                JsExecScope::DedicatedWorker => SpecType::Js(JsSpecType::DedicatedWorker),
            },
        }
    }
}

/// An executed JS test entry's test type, viz.,
#[derive(Clone, Copy, Debug, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum JsExecScope {
    /// A `*.worker.js` test. See also [WPT upstream docs.' "Dedicated worker test (`.worker.js`)"
    /// section][upstream].
    ///
    /// [upstream]: https://web-platform-tests.org/writing-tests/testharness.html#dedicated-worker-tests-worker-js
    DedicatedWorker,
}

const ROOT_DIR_FX_MOZILLA_STR: &str = "testing/web-platform/mozilla";
const ROOT_DIR_FX_MOZILLA_COMPONENTS: &[&str] = &["testing", "web-platform", "mozilla"];
const ROOT_DIR_FX_UPSTREAM_STR: &str = "testing/web-platform";
const ROOT_DIR_FX_UPSTREAM_COMPONENTS: &[&str] = &["testing", "web-platform"];
const ROOT_DIR_SERVO_WEBGPU_STR: &str = "tests/wpt/webgpu";
const ROOT_DIR_SERVO_WEBGPU_COMPONENTS: &[&str] = &["tests", "wpt", "webgpu"];

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TestEntryPath<'a> {
    pub spec_path: SpecPath<'a>,
    pub test_entry: TestEntry<'a>,
}

impl<'a> TestEntryPath<'a> {
    pub fn from_execution_report(
        browser: Browser,
        test_url_path: &'a str,
    ) -> Result<Self, ExecutionReportPathError<'a>> {
        let err = || ExecutionReportPathError { test_url_path };

        let (root_dir, path) = browser
            .strip_wpt_url_prefix(test_url_path)
            .ok_or_else(err)?;

        if path.contains('\\') {
            return Err(err());
        }

        let (path, variant) = match path.split('/').next_back() {
            Some(path_and_maybe_variants) => match path_and_maybe_variants.find('?') {
                Some(query_params_start_idx) => (
                    &path[..path.len() - (path_and_maybe_variants.len() - query_params_start_idx)],
                    Some(&path_and_maybe_variants[query_params_start_idx..]),
                ),
                None => (path, None),
            },
            None => return Err(err()),
        };

        let mut path = Cow::<'_, Utf8Path>::from(Utf8Path::new(path));

        let (test_entry_type, base_name) =
            TestEntryType::from_base_name(path.file_name().ok_or_else(err)?).ok_or_else(err)?;
        let spec_type = test_entry_type.spec_type();

        path = path.with_file_name(base_name).into();

        Ok(Self {
            spec_path: SpecPath {
                root_dir,
                path,
                r#type: spec_type,
            },
            test_entry: TestEntry {
                r#type: test_entry_type,
                variant: variant.map(Into::into),
            },
        })
    }

    pub fn from_metadata_test(
        browser: Browser,
        rel_meta_file_path: &'a Path,
        test_name: &'a str,
    ) -> Result<Self, MetadataTestEntryPathError<'a>> {
        let rel_meta_file_path = Utf8Path::new(rel_meta_file_path.to_str().ok_or(
            MetadataTestEntryPathError {
                rel_meta_file_path,
                test_name,
            },
        )?);
        let err = || MetadataTestEntryPathError {
            rel_meta_file_path: rel_meta_file_path.as_std_path(),
            test_name,
        };
        let (spec_type, rel_meta_file_path) = {
            let test_base_name = rel_meta_file_path
                .as_str()
                .strip_suffix(".ini")
                .ok_or_else(err)?;

            let (spec_type, stripped) = SpecType::from_base_name(test_base_name).ok_or_else(err)?;

            (spec_type, Utf8Path::new(stripped))
        };

        let (root_dir, path) = browser
            .strip_wpt_root_dir_prefix(rel_meta_file_path)
            .map_err(|_e| err())?;

        let Ok(path) = path.strip_prefix("meta/") else {
            return Err(err());
        };

        let (base_name, variant) = Self::split_test_base_name_from_variant(test_name);

        let (js_exec_scope, base_name) = spec_type
            .validate_test_entry_base_name(base_name)
            .ok_or_else(err)?;

        if path.components().next_back() != Some(Utf8Component::Normal(base_name)) {
            return Err(err());
        }

        Ok(Self {
            spec_path: SpecPath {
                root_dir,
                path: path.into(),
                r#type: spec_type,
            },
            test_entry: TestEntry {
                r#type: js_exec_scope,
                variant: variant.map(Into::into),
            },
        })
    }

    fn split_test_base_name_from_variant(url_ish_name: &'a str) -> (&'a str, Option<&'a str>) {
        match url_ish_name.find('?') {
            Some(query_params_start_idx) => (
                &url_ish_name[..url_ish_name.len() - (url_ish_name.len() - query_params_start_idx)],
                Some(&url_ish_name[query_params_start_idx..]),
            ),
            None => (url_ish_name, None),
        }
    }

    pub fn into_owned(self) -> TestEntryPath<'static> {
        let Self {
            spec_path:
                SpecPath {
                    root_dir,
                    path,
                    r#type,
                },
            test_entry:
                TestEntry {
                    r#type: js_exec_scope,
                    variant,
                },
        } = self;

        TestEntryPath {
            spec_path: SpecPath {
                root_dir: root_dir.clone(),
                path: path.clone().into_owned().into(),
                r#type,
            },
            test_entry: TestEntry {
                r#type: js_exec_scope,
                variant: variant.clone().map(|v| v.into_owned().into()),
            },
        }
    }

    pub(crate) fn test_name(&self) -> impl Display + '_ {
        let Self {
            spec_path:
                SpecPath {
                    root_dir: _,
                    path,
                    r#type: _,
                },
            test_entry:
                TestEntry {
                    r#type: js_exec_scope,
                    variant,
                },
        } = self;
        let base_name = path.file_name().unwrap();
        let file_extension = js_exec_scope.file_extension();

        lazy_format!(move |f| {
            write!(f, "{base_name}{file_extension}")?;
            if let Some(variant) = variant {
                write!(f, "{variant}")?;
            }
            Ok(())
        })
    }

    pub(crate) fn runner_url_path(&self) -> impl Display + '_ {
        let Self {
            spec_path:
                SpecPath {
                    root_dir,
                    path,
                    r#type: _,
                },
            test_entry: _,
        } = self;
        lazy_format!(move |f| write!(
            f,
            "{}{}/{}",
            root_dir.url_prefix(),
            path.components().dropping_back(1).join_with('/'),
            self.test_name(),
        ))
    }

    pub(crate) fn rel_metadata_path(&self) -> impl Display + '_ {
        let Self {
            spec_path:
                SpecPath {
                    root_dir,
                    path,
                    r#type,
                },
            test_entry:
                TestEntry {
                    r#type: _,
                    variant: _,
                },
        } = self;

        let root_dir_dir = root_dir
            .components()
            .chain(["meta"].iter().cloned())
            .join_with(std::path::MAIN_SEPARATOR);
        let file_extension = r#type.file_extension();

        lazy_format!(move |f| {
            write!(
                f,
                "{root_dir_dir}{}{path}{file_extension}.ini",
                std::path::MAIN_SEPARATOR
            )
        })
    }
}

/// An error encountered during [`TestEntryPath::from_execution_report`].
#[derive(Debug)]
pub struct ExecutionReportPathError<'a> {
    pub(crate) test_url_path: &'a str,
}

impl Display for ExecutionReportPathError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { test_url_path } = self;
        write!(
            f,
            concat!(
                "failed to derive test path from execution report's entry ",
                "for a test at URL path {:?}"
            ),
            test_url_path
        )
    }
}

/// An error encountered during [`TestEntryPath::from_metadata_test`].
#[derive(Debug)]
pub struct MetadataTestEntryPathError<'a> {
    rel_meta_file_path: &'a Path,
    test_name: &'a str,
}

impl Display for MetadataTestEntryPathError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            rel_meta_file_path,
            test_name,
        } = self;
        write!(
            f,
            "failed to derive test path from relative metadata path {:?} and test name {:?}",
            rel_meta_file_path, test_name
        )
    }
}

/// A root directory from which WPT tests and metadata are based. Based on a specific [`Browser`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum RootDir {
    Firefox(FirefoxRootDir),
    Servo(ServoRootDir),
}

impl RootDir {
    /// NOTE: Keep this implementation in sync with [`Browser::strip_wpt_url_prefix`].
    fn url_prefix(&self) -> &str {
        match self {
            RootDir::Firefox(root_dir) => match root_dir {
                FirefoxRootDir::Upstream => "",
                FirefoxRootDir::Mozilla => "_mozilla/",
            },
            RootDir::Servo(ServoRootDir::WebGpu) => "_webgpu/",
        }
    }

    /// NOTE: Keep this implementation in sync with [`Browser::strip_wpt_root_dir_prefix`].
    fn components(&self) -> impl Iterator<Item = &str> + Clone {
        match self {
            RootDir::Firefox(root_dir) => match root_dir {
                FirefoxRootDir::Upstream => ROOT_DIR_FX_UPSTREAM_COMPONENTS,
                FirefoxRootDir::Mozilla => ROOT_DIR_FX_MOZILLA_COMPONENTS,
            },
            RootDir::Servo(ServoRootDir::WebGpu) => ROOT_DIR_SERVO_WEBGPU_COMPONENTS,
        }
        .iter()
        .cloned()
    }
}

/// Subset of [`RootDir`] for [`Browser::Firefox`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum FirefoxRootDir {
    /// A public test available at some point in the history of [WPT upstream]. Note that while
    /// a test may be public, metadata associated with it is in a private location.
    ///
    /// [WPT upstream]: https://github.com/web-platform-tests/wpt
    Upstream,
    /// A private test specific to Firefox.
    Mozilla,
}

impl From<FirefoxRootDir> for RootDir {
    fn from(value: FirefoxRootDir) -> Self {
        Self::Firefox(value)
    }
}

/// Subset of [`RootDir`] for [`Browser::Servo`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ServoRootDir {
    /// A WebGPU CTS test vendored into Servo's source tree.
    WebGpu,
}

impl From<ServoRootDir> for RootDir {
    fn from(value: ServoRootDir) -> Self {
        Self::Servo(value)
    }
}

fn strip_suffix_with_value<'a, T>(s: &'a str, suffix: &str, t: T) -> Option<(T, &'a str)> {
    s.strip_suffix(suffix).map(|some| (t, some))
}

#[test]
fn parse_test_entry_path() {
    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Firefox,
            Path::new("testing/web-platform/mozilla/meta/blarg/cts.https.html.ini"),
            "cts.https.html?stuff=things"
        )
        .unwrap(),
        TestEntryPath {
            spec_path: SpecPath {
                root_dir: FirefoxRootDir::Mozilla.into(),
                path: Utf8Path::new("blarg/cts.https").into(),
                r#type: SpecType::Html,
            },
            test_entry: TestEntry {
                r#type: TestEntryType::Html,
                variant: Some("?stuff=things".into()),
            }
        }
    );

    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Firefox,
            Path::new("testing/web-platform/meta/stuff/things/cts.https.html.ini"),
            "cts.https.html"
        )
        .unwrap(),
        TestEntryPath {
            spec_path: SpecPath {
                root_dir: FirefoxRootDir::Upstream.into(),
                path: Utf8Path::new("stuff/things/cts.https").into(),
                r#type: SpecType::Html,
            },
            test_entry: TestEntry {
                r#type: TestEntryType::Html,
                variant: None
            }
        }
    );

    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Servo,
            Path::new("tests/wpt/webgpu/meta/webgpu/cts.https.html.ini"),
            "cts.https.html?stuff=things"
        )
        .unwrap(),
        TestEntryPath {
            spec_path: SpecPath {
                root_dir: ServoRootDir::WebGpu.into(),
                path: Utf8Path::new("webgpu/cts.https").into(),
                r#type: SpecType::Html,
            },
            test_entry: TestEntry {
                r#type: TestEntryType::Html,
                variant: Some("?stuff=things".into()),
            }
        }
    );

    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Servo,
            Path::new("tests/wpt/webgpu/meta/webgpu/do_the_thing.worker.js.ini"),
            "do_the_thing.worker.html"
        )
        .unwrap(),
        TestEntryPath {
            spec_path: SpecPath {
                root_dir: ServoRootDir::WebGpu.into(),
                path: Utf8Path::new("webgpu/do_the_thing").into(),
                r#type: SpecType::Js(JsSpecType::DedicatedWorker),
            },
            test_entry: TestEntry {
                r#type: TestEntryType::Js {
                    exec_scope: JsExecScope::DedicatedWorker
                },
                variant: None,
            }
        }
    );

    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Servo,
            Path::new("tests/wpt/webgpu/meta/webgpu/do_the_thing.worker.js.ini"),
            "do_the_thing.worker.html?foo=bar"
        )
        .unwrap(),
        TestEntryPath {
            spec_path: SpecPath {
                root_dir: ServoRootDir::WebGpu.into(),
                path: Utf8Path::new("webgpu/do_the_thing").into(),
                r#type: SpecType::Js(JsSpecType::DedicatedWorker),
            },
            test_entry: TestEntry {
                r#type: TestEntryType::Js {
                    exec_scope: JsExecScope::DedicatedWorker
                },
                variant: Some("?foo=bar".into()),
            }
        }
    );
}

#[test]
fn report_meta_match() {
    macro_rules! assert_test_matches_meta {
        ($browser:expr, $test_run_path:expr, $rel_meta_path:expr, $test_section_header:expr) => {
            assert_eq!(
                TestEntryPath::from_execution_report($browser, $test_run_path).unwrap(),
                TestEntryPath::from_metadata_test(
                    $browser,
                    Path::new($rel_meta_path),
                    $test_section_header
                )
                .unwrap()
            );
            assert_eq!(
                format!(
                    "/{}",
                    TestEntryPath::from_execution_report($browser, $test_run_path)
                        .unwrap()
                        .runner_url_path()
                ),
                $test_run_path,
            );
        };
    }

    assert_test_matches_meta!(
        Browser::Firefox,
        "/_mozilla/blarg/cts.https.html?stuff=things",
        "testing/web-platform/mozilla/meta/blarg/cts.https.html.ini",
        "cts.https.html?stuff=things"
    );

    assert_test_matches_meta!(
        Browser::Firefox,
        "/blarg/cts.https.html?stuff=things",
        "testing/web-platform/meta/blarg/cts.https.html.ini",
        "cts.https.html?stuff=things"
    );

    assert_test_matches_meta!(
        Browser::Servo,
        "/_webgpu/webgpu/cts.https.html?stuff=things",
        "tests/wpt/webgpu/meta/webgpu/cts.https.html.ini",
        "cts.https.html?stuff=things"
    );
}

#[test]
fn report_meta_reject() {
    macro_rules! assert_test_rejects_meta {
        (
            $browser: expr,
            $test_run_path:expr,
            $rel_meta_path:expr,
            $test_section_header:expr
        ) => {
            assert_ne!(
                TestEntryPath::from_execution_report($browser, $test_run_path).unwrap(),
                TestEntryPath::from_metadata_test(
                    $browser,
                    Path::new($rel_meta_path),
                    $test_section_header
                )
                .unwrap()
            )
        };
    }

    assert_test_rejects_meta!(
        Browser::Firefox,
        "/blarg/cts.https.html?stuff=things",
        // Wrong: the `mozilla` component shouldn't be after `web-platform`
        "testing/web-platform/mozilla/meta/blarg/cts.https.html.ini",
        "cts.https.html?stuff=things"
    );

    assert_test_rejects_meta!(
        Browser::Firefox,
        "/_mozilla/blarg/cts.https.html?stuff=things",
        // Wrong: missing the `mozilla` component after `web-platform`
        "testing/web-platform/meta/blarg/cts.https.html.ini",
        "cts.https.html?stuff=things"
    );
}

#[test]
fn runner_url_path() {
    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Firefox,
            Path::new("testing/web-platform/meta/blarg/stuff.https.html.ini"),
            "stuff.https.html"
        )
        .unwrap()
        .runner_url_path()
        .to_string(),
        "blarg/stuff.https.html",
    );

    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Firefox,
            Path::new("testing/web-platform/meta/blarg/stuff.https.html.ini"),
            "stuff.https.html?win"
        )
        .unwrap()
        .runner_url_path()
        .to_string(),
        "blarg/stuff.https.html?win",
    );

    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Firefox,
            Path::new("testing/web-platform/mozilla/meta/blarg/stuff.https.html.ini"),
            "stuff.https.html"
        )
        .unwrap()
        .runner_url_path()
        .to_string(),
        "_mozilla/blarg/stuff.https.html",
    );

    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Firefox,
            Path::new("testing/web-platform/mozilla/meta/blarg/stuff.https.html.ini"),
            "stuff.https.html?win"
        )
        .unwrap()
        .runner_url_path()
        .to_string(),
        "_mozilla/blarg/stuff.https.html?win",
    );

    assert_eq!(
        TestEntryPath::from_metadata_test(
            Browser::Servo,
            Path::new("tests/wpt/webgpu/meta/webgpu/cts.https.html.ini"),
            "cts.https.html?win"
        )
        .unwrap()
        .runner_url_path()
        .to_string(),
        "_webgpu/webgpu/cts.https.html?win",
    );
}
