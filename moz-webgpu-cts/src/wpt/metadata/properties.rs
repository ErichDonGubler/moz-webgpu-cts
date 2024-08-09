use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Display, Formatter},
    num::NonZeroUsize,
    ops::{BitOr, BitOrAssign, Index, IndexMut},
};

use enum_map::EnumMap;
use enumset::{EnumSet, EnumSetType};
use itertools::Itertools;
use serde::Serialize;

use crate::wpt::metadata::{maybe_collapsed::MaybeCollapsed, BuildProfile, Platform};

/// A non-empty set of expected outcomes in a [`Test`] or [`Subtest`].
///
/// The default expected test outcome is a "good" outcome, where testing passes. The `Out` type
/// parameter should return this value in its implementation of `Default`.
///
/// [`Test`]: crate::metadata::Test
/// [`Subtest`]: crate::metadata::Subtest
#[derive(Clone, Copy, Serialize)]
pub struct Expected<Out>(EnumSet<Out>)
where
    Out: EnumSetType;

impl<Out> Default for Expected<Out>
where
    Out: Default + EnumSetType,
{
    fn default() -> Self {
        Self::permanent(Out::default())
    }
}

impl<Out> Expected<Out>
where
    Out: EnumSetType,
{
    /// Returns [`None`] if `outcomes` is empty.
    #[track_caller]
    pub fn new(outcomes: EnumSet<Out>) -> Option<Self> {
        (!outcomes.is_empty()).then_some(Self(outcomes))
    }

    pub fn permanent(outcome: Out) -> Self {
        Self(EnumSet::from_iter([outcome]))
    }

    #[track_caller]
    pub fn intermittent(outcomes: EnumSet<Out>) -> Option<Self> {
        if outcomes.len() <= 1 {
            None
        } else {
            Some(Self::new(outcomes).unwrap())
        }
    }

    pub fn inner(&self) -> EnumSet<Out> {
        let Self(inner) = self;
        *inner
    }

    pub fn len(&self) -> NonZeroUsize {
        self.inner()
            .len()
            .try_into()
            .expect("invariant violation: empty `Expected`")
    }

    pub fn is_permanent(&self) -> bool {
        self.len().get() == 1
    }

    pub fn as_permanent(&self) -> Option<Out> {
        self.is_permanent().then(|| self.iter().next().unwrap())
    }

    pub fn iter(&self) -> impl Iterator<Item = Out> {
        self.inner().iter()
    }

    pub fn is_disjoint(&self, rep: EnumSet<Out>) -> bool {
        self.inner().is_disjoint(rep)
    }

    pub fn is_superset(&self, rep: &Self) -> bool
    where
        Out: std::fmt::Debug + Default + EnumSetType,
    {
        self.inner().is_superset(rep.inner())
    }
}

impl<Out> Display for Expected<Out>
where
    Out: Display + EnumSetType,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(perma) = self.as_permanent() {
            write!(f, "{perma}")
        } else {
            f.debug_list()
                .entries(
                    self.iter()
                        .map(|out| format::Debug(move |f| write!(f, "{out}"))),
                )
                .finish()
        }
    }
}

impl<Out> Debug for Expected<Out>
where
    Out: Debug + EnumSetType,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<Out> BitOr for Expected<Out>
where
    Out: EnumSetType,
{
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        let Self(lhs) = self;
        let Self(rhs) = rhs;

        Self(lhs | rhs)
    }
}

impl<Out> BitOrAssign for Expected<Out>
where
    Out: EnumSetType,
{
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl<Out> BitOr<EnumSet<Out>> for Expected<Out>
where
    Out: EnumSetType,
{
    type Output = Self;

    fn bitor(self, rhs: EnumSet<Out>) -> Self::Output {
        let Self(lhs) = self;

        Self(lhs | rhs)
    }
}

impl<Out> BitOrAssign<EnumSet<Out>> for Expected<Out>
where
    Out: EnumSetType,
{
    fn bitor_assign(&mut self, rhs: EnumSet<Out>) {
        *self = *self | rhs;
    }
}

impl<Out> BitOr<Out> for Expected<Out>
where
    Out: EnumSetType,
{
    type Output = Self;

    fn bitor(self, rhs: Out) -> Self::Output {
        let Self(lhs) = self;

        Self(lhs | rhs)
    }
}

impl<Out> BitOrAssign<Out> for Expected<Out>
where
    Out: EnumSetType,
{
    fn bitor_assign(&mut self, rhs: Out) {
        *self = *self | rhs;
    }
}

impl<Out> PartialEq for Expected<Out>
where
    Out: EnumSetType + Eq,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner() == other.inner()
    }
}

impl<Out> PartialEq<Out> for Expected<Out>
where
    Out: EnumSetType + Eq,
{
    fn eq(&self, other: &Out) -> bool {
        self.inner() == *other
    }
}

impl<Out> Eq for Expected<Out> where Out: EnumSetType + Eq {}

/// A completely flat representation of [`NormalizedPropertyValue`] suitable for byte
/// representation in memory.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct ExpandedPropertyValue<T>(ExpandedPropertyValueData<T>);

impl<T> Index<(Platform, BuildProfile)> for ExpandedPropertyValue<T> {
    type Output = T;

    fn index(&self, (platform, build_profile): (Platform, BuildProfile)) -> &Self::Output {
        &self.0[platform][build_profile]
    }
}

impl<Out> IndexMut<(Platform, BuildProfile)> for ExpandedPropertyValue<Out> {
    fn index_mut(
        &mut self,
        (platform, build_profile): (Platform, BuildProfile),
    ) -> &mut Self::Output {
        &mut self.0[platform][build_profile]
    }
}

impl<T> ExpandedPropertyValue<T>
where
    T: Clone,
{
    pub fn unconditional(value: T) -> Self {
        Self::from_query(|_, _| value.clone())
    }
}

impl<T> ExpandedPropertyValue<T> {
    pub(crate) fn into_iter(self) -> impl Iterator<Item = ((Platform, BuildProfile), T)> {
        let Self(inner) = self;
        inner.into_iter().flat_map(|(platform, outcomes)| {
            outcomes
                .into_iter()
                .map(move |(build_profile, outcomes)| ((platform, build_profile), outcomes))
        })
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = ((Platform, BuildProfile), &T)> {
        self.inner().iter().flat_map(|(platform, outcomes)| {
            outcomes
                .iter()
                .map(move |(build_profile, outcomes)| ((platform, build_profile), outcomes))
        })
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = ((Platform, BuildProfile), &mut T)> {
        self.inner_mut()
            .iter_mut()
            .flat_map(|(platform, outcomes)| {
                outcomes
                    .iter_mut()
                    .map(move |(build_profile, outcomes)| ((platform, build_profile), outcomes))
            })
    }

    pub(crate) fn map<U, F>(self, f: F) -> ExpandedPropertyValue<U>
    where
        F: FnMut(T) -> U,
    {
        let mut f = f;
        ExpandedPropertyValue(
            self.into_inner()
                .map(|_platform, by_build_profile| by_build_profile.map(|_build_profile, t| f(t))),
        )
    }

    pub(crate) fn map_with<U, F>(self, f: F) -> ExpandedPropertyValue<U>
    where
        F: FnMut((Platform, BuildProfile), T) -> U,
    {
        let mut f = f;
        ExpandedPropertyValue(self.into_inner().map(|platform, by_build_profile| {
            by_build_profile.map(|build_profile, t| f((platform, build_profile), t))
        }))
    }

    fn into_inner(self) -> ExpandedPropertyValueData<T> {
        let Self(inner) = self;
        inner
    }

    pub(crate) fn inner(&self) -> &ExpandedPropertyValueData<T> {
        let Self(inner) = self;
        inner
    }

    fn inner_mut(&mut self) -> &mut ExpandedPropertyValueData<T> {
        let Self(inner) = self;
        inner
    }

    pub(crate) fn as_ref(&self) -> ExpandedPropertyValue<&T> {
        ExpandedPropertyValue::from_query(|platform, build_profile| {
            &self[(platform, build_profile)]
        })
    }
}

impl<T> ExpandedPropertyValue<T> {
    pub fn from_query<F>(f: F) -> Self
    where
        F: FnMut(Platform, BuildProfile) -> T,
    {
        let mut f = f;
        Self(EnumMap::from_fn(|platform| {
            EnumMap::from_fn(|build_profile| f(platform, build_profile))
        }))
    }
}

pub type ExpandedPropertyValueData<T> = EnumMap<Platform, EnumMap<BuildProfile, T>>;

#[test]
fn expanded_expected_is_tiny() {
    use crate::metadata::{SubtestOutcome, TestOutcome};
    use std::mem::size_of;

    assert_eq!(size_of::<ExpandedPropertyValue<Expected<TestOutcome>>>(), 6);
    assert_eq!(
        size_of::<ExpandedPropertyValue<Expected<SubtestOutcome>>>(),
        6
    );
}

/// A normalized representation of a property in [`TestProps`], which collapses backwards along the
/// following branching factors:
///
/// * [`Platform`]
/// * [`BuildProfile`]
///
/// Yes, the type is _gnarly_. Sorry about that. This is some complex domain, okay? 😆😭
///
/// [`TestProps`]: crate::metadata::TestProps
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPropertyValue<T>(NormalizedPropertyValueData<T>);

impl<T> Default for NormalizedPropertyValue<T>
where
    T: Default,
{
    fn default() -> Self {
        Self(MaybeCollapsed::Collapsed(MaybeCollapsed::Collapsed(
            Default::default(),
        )))
    }
}

impl<T> NormalizedPropertyValue<T> {
    pub fn inner(&self) -> &NormalizedPropertyValueData<T> {
        let Self(inner) = self;
        inner
    }
}

impl<T> NormalizedPropertyValue<T>
where
    T: Clone + Eq,
{
    pub(crate) fn from_expanded(outcomes: ExpandedPropertyValue<T>) -> Self {
        Self(
            if let Ok(uniform) = outcomes
                .iter()
                .map(|(_, outcome)| outcome)
                .all_equal_value()
            {
                MaybeCollapsed::Collapsed(MaybeCollapsed::Collapsed(uniform.clone()))
            } else {
                let per_bp = |outcomes_by_bp: &EnumMap<_, _>| {
                    outcomes_by_bp
                        .iter()
                        .map(|(bp, outcomes): (_, &T)| (bp, outcomes.clone()))
                        .collect()
                };
                if let Ok(uniform_per_platform) = outcomes
                    .inner()
                    .iter()
                    .map(|(_, outcomes)| outcomes)
                    .all_equal_value()
                {
                    MaybeCollapsed::Collapsed(MaybeCollapsed::Expanded(per_bp(
                        uniform_per_platform,
                    )))
                } else {
                    MaybeCollapsed::Expanded(
                        outcomes
                            .inner()
                            .iter()
                            .map(|(platform, outcomes_by_bp)| {
                                if let Ok(uniform_per_bp) = outcomes_by_bp
                                    .iter()
                                    .map(|(_, outcomes)| outcomes.clone())
                                    .all_equal_value()
                                {
                                    (platform, MaybeCollapsed::Collapsed(uniform_per_bp))
                                } else {
                                    (platform, MaybeCollapsed::Expanded(per_bp(outcomes_by_bp)))
                                }
                            })
                            .collect(),
                    )
                }
            },
        )
    }
}

/// Data from a [`NormalizedPropertyValue`]. A normalized form of [`NonNormalizedPropertyValue`].
pub type NormalizedPropertyValueData<T> = Normalized<Platform, Normalized<BuildProfile, T>>;

/// A value that is either `V` or a set of `V`s branched on by `K`.
pub type Normalized<K, V> = MaybeCollapsed<V, BTreeMap<K, V>>;

pub type NonNormalizedPropertyValue<T> = BTreeMap<Platform, BTreeMap<BuildProfile, T>>;
