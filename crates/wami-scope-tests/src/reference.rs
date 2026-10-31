//! The reference store: the world's edges followed in memory, each bound
//! name kept by a predicate. It gives every [`Shape`] its meaning — what
//! the suite expects of a real store — and runs as a store itself.

use std::collections::BTreeSet;

use wami_scope::Narrowing;

use crate::port::{Row, Shape, Store};
use crate::world::{Kind, Resource, World};

/// The world in memory, as a store.
#[derive(Default)]
pub struct Reference {
    resources: Vec<Resource>,
    edges: Vec<(String, &'static str, String)>,
}

impl Reference {
    /// Whether `arn` is hidden by a store rule: archived, or under an
    /// archived container (a prefix of it is an archived resource).
    fn hidden(&self, arn: &str) -> bool {
        self.resources
            .iter()
            .any(|r| r.archived && (r.arn == arn || arn.starts_with(&format!("{}/", r.arn))))
    }

    fn of_kind(&self, kind: Kind) -> impl Iterator<Item = &Resource> {
        self.resources
            .iter()
            .filter(move |r| r.kind == kind && !self.hidden(&r.arn))
    }

    fn out<'a>(
        &'a self,
        from: &'a str,
        label: &'a str,
        kind: Kind,
    ) -> impl Iterator<Item = &'a Resource> + 'a {
        self.edges
            .iter()
            .filter(move |(f, l, _)| f == from && *l == label)
            .filter_map(move |(_, _, to)| self.resources.iter().find(|r| &r.arn == to))
            .filter(move |r| r.kind == kind && !self.hidden(&r.arn))
    }

    /// Runs `shape`, keeping for each bound name what `keep(name, arn)`
    /// says: the meaning of every shape, with any filter.
    pub fn run_with(&self, shape: &Shape, keep: &dyn Fn(&str, &str) -> bool) -> Vec<Row> {
        let mut rows = match shape {
            Shape::List { kind } => self.list(*kind, None, keep),
            Shape::Lookup { kind, suffix } => self.list(*kind, Some(suffix), keep),
            Shape::Children {
                parent,
                edge,
                child,
            } => self.children(*parent, edge, *child, keep),
            Shape::Path {
                first,
                edge1,
                middle,
                edge2,
                last,
            } => self.path(*first, edge1, *middle, edge2, *last, keep),
            Shape::Exists { kind, edge, target } => self.exists(*kind, edge, *target, keep),
            Shape::Count {
                parent,
                edge,
                child,
            } => self.count(*parent, edge, *child, keep),
            Shape::OrderBy {
                parent,
                edge,
                child,
            } => return self.order_by(*parent, edge, *child, keep),
        };
        rows.sort();
        rows
    }

    fn row(arns: Vec<(&str, &str)>, count: Option<u64>) -> Row {
        Row {
            arns: arns
                .into_iter()
                .map(|(n, a)| (n.to_string(), a.to_string()))
                .collect(),
            count,
        }
    }

    fn list(
        &self,
        kind: Kind,
        suffix: Option<&str>,
        keep: &dyn Fn(&str, &str) -> bool,
    ) -> Vec<Row> {
        self.of_kind(kind)
            .filter(|r| suffix.is_none_or(|s| r.arn.ends_with(s)) && keep("n", &r.arn))
            .map(|r| Self::row(vec![("n", &r.arn)], None))
            .collect()
    }

    fn children(
        &self,
        parent: Kind,
        edge: &str,
        child: Kind,
        keep: &dyn Fn(&str, &str) -> bool,
    ) -> Vec<Row> {
        self.of_kind(parent)
            .filter(|p| keep("p", &p.arn))
            .flat_map(|p| {
                self.out(&p.arn, edge, child)
                    .filter(|c| keep("c", &c.arn))
                    .map(move |c| Self::row(vec![("p", &p.arn), ("c", &c.arn)], None))
            })
            .collect()
    }

    fn path(
        &self,
        first: Kind,
        edge1: &str,
        middle: Kind,
        edge2: &str,
        last: Kind,
        keep: &dyn Fn(&str, &str) -> bool,
    ) -> Vec<Row> {
        self.of_kind(first)
            .filter(|p| keep("p", &p.arn))
            .flat_map(|p| {
                self.out(&p.arn, edge1, middle)
                    .filter(|m| keep("m", &m.arn))
                    .flat_map(move |m| {
                        self.out(&m.arn, edge2, last)
                            .filter(|c| keep("c", &c.arn))
                            .map(move |c| {
                                Self::row(vec![("p", &p.arn), ("m", &m.arn), ("c", &c.arn)], None)
                            })
                    })
            })
            .collect()
    }

    fn exists(
        &self,
        kind: Kind,
        edge: &str,
        target: Kind,
        keep: &dyn Fn(&str, &str) -> bool,
    ) -> Vec<Row> {
        self.of_kind(kind)
            .filter(|p| keep("p", &p.arn))
            .filter(|p| self.out(&p.arn, edge, target).any(|c| keep("c", &c.arn)))
            .map(|p| Self::row(vec![("p", &p.arn)], None))
            .collect()
    }

    fn count(
        &self,
        parent: Kind,
        edge: &str,
        child: Kind,
        keep: &dyn Fn(&str, &str) -> bool,
    ) -> Vec<Row> {
        self.of_kind(parent)
            .filter(|p| keep("p", &p.arn))
            .map(|p| {
                let n = self
                    .out(&p.arn, edge, child)
                    .filter(|c| keep("c", &c.arn))
                    .count();
                Self::row(vec![("p", &p.arn)], Some(n as u64))
            })
            .collect()
    }

    fn order_by(
        &self,
        parent: Kind,
        edge: &str,
        child: Kind,
        keep: &dyn Fn(&str, &str) -> bool,
    ) -> Vec<Row> {
        let mut keyed: Vec<(String, String)> = self
            .of_kind(parent)
            .filter(|p| keep("p", &p.arn))
            .map(|p| {
                let last = self
                    .out(&p.arn, edge, child)
                    .filter(|c| keep("c", &c.arn))
                    .map(|c| c.arn.clone())
                    .max()
                    .unwrap_or_default();
                (last, p.arn.clone())
            })
            .collect();
        keyed.sort();
        keyed
            .into_iter()
            .map(|(_, p)| Self::row(vec![("p", &p)], None))
            .collect()
    }

    /// The rows as a set, for comparisons that ignore order.
    #[must_use]
    pub fn set(rows: &[Row]) -> BTreeSet<Row> {
        rows.iter().cloned().collect()
    }
}

impl Store for Reference {
    fn load(&mut self, world: &World) {
        self.resources.clone_from(&world.resources);
        self.edges = world
            .edges
            .iter()
            .map(|e| (e.from.clone(), e.label, e.to.clone()))
            .collect();
    }

    fn run(&self, shape: &Shape, narrowing: &Narrowing) -> Vec<Row> {
        let lowered = narrowing.lowered();
        self.run_with(shape, &|name, arn| {
            lowered
                .iter()
                .find(|(n, _)| *n == name)
                .is_none_or(|(_, predicate)| predicate.keeps(arn))
        })
    }
}
