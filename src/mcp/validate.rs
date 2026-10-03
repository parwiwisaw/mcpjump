//! Checks tool params against the tool's input schema before the call, with
//! bounded work: no remote references, linear-time regexes, a node and
//! depth cap, and a deadline.

use std::error::Error as StdError;
use std::time::Duration;

use jsonschema::{PatternOptions, Retrieve, Uri};
use serde_json::{Map, Value};

use crate::error::{Error, ErrorKind};
use crate::sys::worker::run_within;

/// Most JSON nodes in one input schema.
pub const MAX_SCHEMA_NODES: u64 = 10_000;

/// Most compiled size for one schema regex, and for its lazy DFA.
const REGEX_SIZE_LIMIT: usize = 1024 * 1024;

/// The keywords that reference another schema.
const REF_KEYWORDS: [&str; 3] = ["$ref", "$dynamicRef", "$recursiveRef"];

/// How a JSON value passed its structure limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Excess {
    /// Nested deeper than allowed.
    Depth,
    /// More nodes than allowed.
    Nodes,
}

/// The first structure limit `value` passes, if any. The top-level value
/// is at depth 1. Iterative, so a deep value cannot overflow the stack;
/// stops at the first excess node.
#[must_use]
pub fn shape(value: &Value, max_depth: u64, max_nodes: u64) -> Option<Excess> {
    let mut stack = vec![(value, 1_u64)];
    let mut nodes = 0_u64;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if depth > max_depth {
            return Some(Excess::Depth);
        }
        if nodes > max_nodes {
            return Some(Excess::Nodes);
        }
        match value {
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(map) => stack.extend(map.values().map(|item| (item, depth + 1))),
            _ => {}
        }
    }
    None
}

/// Returns params as an object after checking they are a JSON object no
/// deeper than `max_depth`.
///
/// # Errors
/// `invalid_params`.
pub fn check_params(params: Value, max_depth: u64) -> Result<Map<String, Value>, Error> {
    if shape(&params, max_depth, u64::MAX).is_some() {
        return Err(Error::new(
            ErrorKind::InvalidParams,
            format!("params are nested deeper than max_json_depth ({max_depth})"),
        ));
    }
    match params {
        Value::Object(arguments) => Ok(arguments),
        _ => Err(Error::new(
            ErrorKind::InvalidParams,
            "params must be a JSON object",
        )),
    }
}

/// Validates `params` against `schema` on a separate thread. On timeout
/// the thread is left to finish on its own and the tool is not called.
///
/// # Errors
/// `schema_too_complex` if the schema passes a limit, references anything
/// outside itself, does not compile, or takes longer than `timeout`;
/// `invalid_params`, with the JSON pointer of the failing value, if the
/// params do not match.
pub fn validate(
    schema: &Value,
    params: &Value,
    max_depth: u64,
    timeout: Duration,
) -> Result<(), Error> {
    if let Some(excess) = shape(schema, max_depth, MAX_SCHEMA_NODES) {
        return Err(too_complex(match excess {
            Excess::Depth => "is nested deeper than max_json_depth",
            Excess::Nodes => "has more than 10000 nodes",
        }));
    }
    if has_external_ref(schema) {
        return Err(too_complex("references a schema outside itself"));
    }
    let (schema, params) = (schema.clone(), params.clone());
    run_within(Box::new(move || check(&schema, &params)), timeout)
        .unwrap_or_else(|| Err(too_complex("took too long to check")))
}

/// Whether any reference keyword points outside the document. Only
/// fragment references (`#...`) are local. Runs after [`shape`], so the
/// walk is bounded by [`MAX_SCHEMA_NODES`].
fn has_external_ref(schema: &Value) -> bool {
    let mut stack = vec![schema];
    while let Some(value) = stack.pop() {
        match value {
            Value::Array(items) => stack.extend(items),
            Value::Object(map) => {
                let external = REF_KEYWORDS.iter().any(|keyword| {
                    map.get(*keyword)
                        .is_some_and(|target| !target.as_str().is_some_and(|t| t.starts_with('#')))
                });
                if external {
                    return true;
                }
                stack.extend(map.values());
            }
            _ => {}
        }
    }
    false
}

fn check(schema: &Value, params: &Value) -> Result<(), Error> {
    let patterns = PatternOptions::regex()
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT);
    let validator = jsonschema::options()
        .with_retriever(DenyAll)
        .with_pattern_options(patterns)
        .build(schema)
        .map_err(|error| too_complex(&format!("does not compile ({})", error.kind().keyword())))?;
    validator.validate(params).map_err(|error| {
        Error::new(
            ErrorKind::InvalidParams,
            format!(
                "params do not match the tool's input schema ({})",
                error.kind().keyword()
            ),
        )
        .with_path(error.instance_path().as_str())
    })
}

fn too_complex(what: &str) -> Error {
    Error::new(
        ErrorKind::SchemaTooComplex,
        format!("the tool's input schema {what}; the tool was not called"),
    )
}

/// Refuses every lookup: a schema may only reference itself.
struct DenyAll;

impl Retrieve for DenyAll {
    fn retrieve(&self, _uri: &Uri<String>) -> Result<Value, Box<dyn StdError + Send + Sync>> {
        Err("mcpjump does not fetch schemas".into())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    fn kind(schema: &Value, params: &Value) -> Option<ErrorKind> {
        validate(schema, params, 64, WAIT)
            .err()
            .map(|error| error.kind())
    }

    #[test]
    fn shape_counts_depth_and_nodes() {
        let value = json!({"a": [1, {"b": 2}]});
        assert_eq!(shape(&value, 4, 5), None);
        assert_eq!(shape(&value, 3, 5), Some(Excess::Depth));
        assert_eq!(shape(&value, 4, 4), Some(Excess::Nodes));
    }

    #[test]
    fn params_must_be_a_shallow_object() {
        let arguments = check_params(json!({"a": 1}), 2).unwrap();
        assert_eq!(arguments["a"], 1);
        let not_object = check_params(json!([1]), 2).unwrap_err();
        assert_eq!(not_object.kind(), ErrorKind::InvalidParams);
        let deep = check_params(json!({"a": {"b": 1}}), 2).unwrap_err();
        assert_eq!(deep.kind(), ErrorKind::InvalidParams);
    }

    #[test]
    fn a_failing_value_is_reported_by_pointer_and_keyword() {
        let schema = json!({"type": "object", "properties": {"n": {"type": "integer"}}});
        assert_eq!(kind(&schema, &json!({"n": 1})), None);
        let error = validate(&schema, &json!({"n": "x"}), 64, WAIT).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        assert_eq!(error.path(), Some("/n"));
        assert!(error.message().contains("(type)"));
    }

    #[test]
    fn local_references_resolve_and_others_are_refused() {
        let local = json!({"$defs": {"n": {"type": "integer"}}, "properties": {"n": {"$ref": "#/$defs/n"}}});
        assert_eq!(
            kind(&local, &json!({"n": "x"})),
            Some(ErrorKind::InvalidParams)
        );
        for keyword in REF_KEYWORDS {
            let external = json!({"items": [{keyword: "https://a.example/s.json"}]});
            assert_eq!(
                kind(&external, &json!({})),
                Some(ErrorKind::SchemaTooComplex)
            );
        }
        let relative = json!({"$ref": "other.json#/x"});
        assert_eq!(
            kind(&relative, &json!({})),
            Some(ErrorKind::SchemaTooComplex)
        );
        let not_text = json!({"$ref": 5});
        assert_eq!(
            kind(&not_text, &json!({})),
            Some(ErrorKind::SchemaTooComplex)
        );
    }

    #[test]
    fn oversized_and_broken_schemas_are_too_complex() {
        let deep = (0..70).fold(json!({}), |inner, _| json!({"not": inner}));
        assert_eq!(kind(&deep, &json!({})), Some(ErrorKind::SchemaTooComplex));
        let wide = json!({"enum": vec![0; 10_001]});
        assert_eq!(kind(&wide, &json!({})), Some(ErrorKind::SchemaTooComplex));
        let bad = json!({"type": 5});
        assert_eq!(kind(&bad, &json!({})), Some(ErrorKind::SchemaTooComplex));
    }

    #[test]
    fn a_backtracking_regex_is_refused_and_a_huge_one_does_not_compile() {
        let backref = json!({"properties": {"s": {"pattern": "(a)\\1"}}});
        assert_eq!(
            kind(&backref, &json!({"s": "aa"})),
            Some(ErrorKind::SchemaTooComplex)
        );
        let huge = json!({"properties": {"s": {"pattern": "\\w{1000}{1000}"}}});
        assert_eq!(
            kind(&huge, &json!({"s": "a"})),
            Some(ErrorKind::SchemaTooComplex)
        );
        let linear = json!({"properties": {"s": {"pattern": "^(a+)+$"}}});
        let evil = format!("{}b", "a".repeat(10_000));
        assert_eq!(
            kind(&linear, &json!({ "s": evil })),
            Some(ErrorKind::InvalidParams)
        );
    }

    #[test]
    fn a_slow_check_times_out_without_a_result() {
        let branches: Vec<Value> = (0..2_000).map(|n| json!({"const": n})).collect();
        let schema = json!({"items": {"anyOf": branches}});
        let params = Value::Array(vec![json!(-1); 5_000]);
        let error = validate(&schema, &params, 64, Duration::ZERO).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SchemaTooComplex);
    }

    #[test]
    fn the_retriever_refuses_every_lookup() {
        let uri = jsonschema::uri::from_str("https://a.example/s.json").unwrap();
        assert!(DenyAll.retrieve(&uri).is_err());
    }
}
