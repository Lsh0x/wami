//! The port a store implements to run the suite: load the world, run a
//! shape under a narrowing, hand back the rows with every bound name's ARN.
//!
//! A [`Shape`] is a query without a syntax — a list, a parent and its
//! children, a path of two edges, an existence test, a count, an ordering,
//! a lookup by name. Each binds names (`n`, or `p`, `m`, `c`) to kinds; the
//! suite compiles one scope per bound name under the action reading that
//! kind stands for ([`Kind::read_action`]), and the store renders only the
//! names the narrowing binds — an unbound name is rendered unfiltered, which
//! is how the suite proves it would see a leak.

use wami_scope::Narrowing;

use crate::world::{Kind, World};

/// A query shape, without a syntax.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Every resource of a kind. Binds `n`.
    List {
        /// The kind listed.
        kind: Kind,
    },
    /// A resource and each of its neighbours along an edge. Binds `p`, `c`;
    /// a row holds both.
    Children {
        /// The tail's kind.
        parent: Kind,
        /// The edge followed.
        edge: &'static str,
        /// The head's kind.
        child: Kind,
    },
    /// Two edges. Binds `p`, `m`, `c`; a row holds the three.
    Path {
        /// The first kind.
        first: Kind,
        /// The first edge.
        edge1: &'static str,
        /// The middle kind.
        middle: Kind,
        /// The second edge.
        edge2: &'static str,
        /// The last kind.
        last: Kind,
    },
    /// A resource that has at least one neighbour along an edge. Binds `p`
    /// (returned) and `c` (tested, never returned).
    Exists {
        /// The kind returned.
        kind: Kind,
        /// The edge tested.
        edge: &'static str,
        /// The neighbour's kind.
        target: Kind,
    },
    /// A resource with the number of its neighbours along an edge. Binds
    /// `p` (returned) and `c` (counted).
    Count {
        /// The kind returned.
        parent: Kind,
        /// The edge counted.
        edge: &'static str,
        /// The neighbours' kind.
        child: Kind,
    },
    /// Resources ordered by their last neighbour's ARN, the neighbour not
    /// returned. Binds `p` (returned) and `c` (ordered by).
    OrderBy {
        /// The kind returned.
        parent: Kind,
        /// The edge followed.
        edge: &'static str,
        /// The neighbours' kind.
        child: Kind,
    },
    /// Resources of a kind whose ARN ends with a suffix (a lookup by name,
    /// across tenants). Binds `n`.
    Lookup {
        /// The kind.
        kind: Kind,
        /// The end of the ARN.
        suffix: String,
    },
}

impl Shape {
    /// The names the shape binds, with their kinds, in order.
    #[must_use]
    pub fn bindings(&self) -> Vec<(&'static str, Kind)> {
        match self {
            Shape::List { kind } | Shape::Lookup { kind, .. } => vec![("n", *kind)],
            Shape::Children { parent, child, .. }
            | Shape::Count { parent, child, .. }
            | Shape::OrderBy { parent, child, .. } => vec![("p", *parent), ("c", *child)],
            Shape::Exists { kind, target, .. } => vec![("p", *kind), ("c", *target)],
            Shape::Path {
                first,
                middle,
                last,
                ..
            } => vec![("p", *first), ("m", *middle), ("c", *last)],
        }
    }

    /// The names a row returns (a tested or counted name is not returned).
    #[must_use]
    pub fn returned(&self) -> Vec<&'static str> {
        match self {
            Shape::List { .. } | Shape::Lookup { .. } => vec!["n"],
            Shape::Children { .. } => vec!["p", "c"],
            Shape::Path { .. } => vec!["p", "m", "c"],
            Shape::Exists { .. } | Shape::Count { .. } | Shape::OrderBy { .. } => vec!["p"],
        }
    }
}

/// One row a store returned: the ARN of each returned name, and the count
/// for [`Shape::Count`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Row {
    /// `(name, arn)`, in the shape's returned order.
    pub arns: Vec<(String, String)>,
    /// [`Shape::Count`]'s count.
    pub count: Option<u64>,
}

impl Row {
    /// The ARN of `name`.
    #[must_use]
    pub fn arn(&self, name: &str) -> Option<&str> {
        self.arns
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, a)| a.as_str())
    }

    /// The row as [`Narrowing::admit`] takes it.
    #[must_use]
    pub fn pairs(&self) -> Vec<(&str, &str)> {
        self.arns
            .iter()
            .map(|(n, a)| (n.as_str(), a.as_str()))
            .collect()
    }
}

/// A store under test.
pub trait Store {
    /// Loads the world: every resource with its ARN, kind, tenant and
    /// `archived` flag, every edge.
    fn load(&mut self, world: &World);

    /// Runs `shape` under `narrowing`: every bound name the narrowing holds
    /// is filtered by its lowered predicate, an unbound name is not; an
    /// archived resource, or one under an archived container, is never
    /// returned (a store rule, not a right). Rows come back with every
    /// returned name's ARN.
    fn run(&self, shape: &Shape, narrowing: &Narrowing) -> Vec<Row>;
}
