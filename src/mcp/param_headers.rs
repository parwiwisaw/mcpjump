//! Modern x-mcp-header validation, generation and encoded size bounds.

use std::collections::{HashMap, HashSet};

use base64::{Engine, prelude::BASE64_STANDARD};
use serde_json::Value;

use reqwest::header::HeaderName;

use crate::error::{Error, ErrorKind};

/// Most `Mcp-Param-*` headers on one request.
pub(crate) const MAX_HEADERS: usize = 32;
/// Largest encoded value of one header.
pub(crate) const MAX_VALUE_BYTES: usize = 8 * 1024;
/// Largest sum of encoded values.
pub(crate) const MAX_TOTAL_BYTES: usize = 32 * 1024;

const PREFIX: &str = "mcp-param-";

/// Checks the `Mcp-Param-*` headers among `headers`.
///
/// # Errors
/// `invalid_params` when a limit is passed.
pub(crate) fn check(headers: &HashMap<HeaderName, String>) -> Result<(), Error> {
    let sizes: Vec<usize> = headers
        .iter()
        .filter(|(name, _)| name.as_str().starts_with(PREFIX))
        .map(|(_, value)| value.len())
        .collect();
    let rule = if sizes.len() > MAX_HEADERS {
        format!("more than {MAX_HEADERS} arguments are mirrored into Mcp-Param-* headers")
    } else if sizes.iter().any(|size| *size > MAX_VALUE_BYTES) {
        format!(
            "an argument mirrored into an Mcp-Param-* header is longer than {MAX_VALUE_BYTES} bytes"
        )
    } else if sizes.iter().sum::<usize>() > MAX_TOTAL_BYTES {
        format!(
            "the arguments mirrored into Mcp-Param-* headers pass {MAX_TOTAL_BYTES} bytes in total"
        )
    } else {
        return Ok(());
    };
    Err(Error::new(ErrorKind::InvalidParams, rule))
}

/// A checked property and its canonical HTTP header name.
pub(crate) type Annotation = (String, HeaderName);

/// Validates the 2026-07-28 top-level primitive annotation rules.
/// Invalid tools are omitted, matching rmcp 3.5.0's Modern filtering.
pub(crate) fn annotations(schema: &Value) -> Option<Vec<Annotation>> {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Some(Vec::new());
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (property, schema) in properties {
        if nested_annotation(schema) {
            return None;
        }
        let Some(raw) = schema.get("x-mcp-header") else {
            continue;
        };
        let header = raw.as_str()?;
        // Checking the suffix separately rejects an empty annotation as well.
        let suffix = HeaderName::from_bytes(header.as_bytes()).ok()?;
        if !seen.insert(suffix) {
            return None;
        }
        if !matches!(
            schema["type"].as_str(),
            Some("string" | "integer" | "boolean")
        ) {
            return None;
        }
        let name = HeaderName::from_bytes(format!("{PREFIX}{header}").as_bytes()).ok()?;
        out.push((property.clone(), name));
    }
    Some(out)
}

/// Searches nested properties iteratively; the bounded response limits its work.
fn nested_annotation(schema: &Value) -> bool {
    let mut pending = vec![schema];
    while let Some(schema) = pending.pop() {
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for schema in properties.values() {
                if schema.get("x-mcp-header").is_some() {
                    return true;
                }
                pending.push(schema);
            }
        }
    }
    false
}

/// Generates primitive argument headers, then checks their encoded sizes.
pub(crate) fn generate(
    annotations: &[Annotation],
    arguments: &Value,
) -> Result<HashMap<HeaderName, String>, Error> {
    let mut headers = HashMap::new();
    for (property, name) in annotations {
        let text = match &arguments[property] {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(boolean) => boolean.to_string(),
            _ => continue,
        };
        let value = encode(&text);
        headers.insert(name.clone(), value);
    }
    check(&headers)?;
    Ok(headers)
}

/// SEP-2243 sentinel encoding, including values that resemble the sentinel.
pub(crate) fn encode(value: &str) -> String {
    let bytes = value.as_bytes();
    let wrap = matches!(bytes.first(), Some(b' ' | b'\t'))
        || matches!(bytes.last(), Some(b' ' | b'\t'))
        || bytes.iter().any(|byte| !(0x20..=0x7e).contains(byte))
        || (value.starts_with("=?base64?") && value.ends_with("?="));
    if wrap {
        format!("=?base64?{}?=", BASE64_STANDARD.encode(value))
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[usize]) -> HashMap<HeaderName, String> {
        let mut map: HashMap<HeaderName, String> = values
            .iter()
            .enumerate()
            .map(|(index, size)| {
                let name = HeaderName::try_from(format!("mcp-param-p{index}")).unwrap();
                (name, "a".repeat(*size))
            })
            .collect();
        map.insert(reqwest::header::ACCEPT, "text/event-stream".to_owned());
        map
    }

    fn outcome(values: &[usize]) -> Result<(), ErrorKind> {
        check(&headers(values)).map_err(|error| error.kind())
    }

    #[test]
    fn limits_hold_at_the_boundary() {
        assert_eq!(outcome(&[1; MAX_HEADERS]), Ok(()));
        assert_eq!(
            outcome(&[
                MAX_VALUE_BYTES,
                MAX_VALUE_BYTES,
                MAX_VALUE_BYTES,
                MAX_VALUE_BYTES
            ]),
            Ok(())
        );
        assert_eq!(
            outcome(&[1; MAX_HEADERS + 1]),
            Err(ErrorKind::InvalidParams)
        );
        assert_eq!(
            outcome(&[MAX_VALUE_BYTES + 1]),
            Err(ErrorKind::InvalidParams)
        );
        assert_eq!(
            outcome(&[MAX_VALUE_BYTES; 5]),
            Err(ErrorKind::InvalidParams)
        );
    }
}

#[cfg(test)]
mod generation_tests {
    use serde_json::json;

    use super::*;

    /// A single top-level annotation under test.
    fn schema(annotation: &Value, kind: &str) -> Value {
        json!({"properties":{"value":{"type":kind,"x-mcp-header":annotation}}})
    }

    /// Validation matches the 2026-07-28 primitive, token and uniqueness rules.
    #[test]
    fn invalid_annotations_and_nested_promotions_are_dropped() {
        for annotation in [
            json!(null),
            json!(5),
            json!(""),
            json!("bad name"),
            json!("é"),
        ] {
            assert!(annotations(&schema(&annotation, "string")).is_none());
        }
        for kind in ["number", "object", "array", "null", "unknown"] {
            assert!(annotations(&schema(&json!("Value"), kind)).is_none());
        }
        let duplicate = json!({"properties":{"a":{"type":"string","x-mcp-header":"Region"},"b":{"type":"boolean","x-mcp-header":"region"}}});
        assert!(annotations(&duplicate).is_none());
        let nested = json!({"properties":{"a":{"properties":{"b":{"properties":{"c":{"x-mcp-header":"C"}}}}}}});
        assert!(annotations(&nested).is_none());
        assert!(annotations(&schema(&json!("a".repeat(65_535)), "string")).is_none());
        assert!(annotations(&json!({})).unwrap().is_empty());
        assert!(
            annotations(&json!({"properties":{"a":{},"b":{"properties":{"c":{}}}}}))
                .unwrap()
                .is_empty()
        );
    }

    /// Every required encoding trigger is distinct, and printable values stay bare.
    #[test]
    fn encoding_covers_whitespace_controls_unicode_and_sentinels() {
        for text in ["", "region", "a b", "~", "=?base64?unfinished", "other?="] {
            assert_eq!(encode(text), text);
        }
        for text in [
            " leading",
            "trailing ",
            "\tleading",
            "trailing\t",
            "a\nb",
            "a\rb",
            "a\tb",
            "\u{7f}",
            "é",
            "=?base64?YQ==?=",
        ] {
            assert_eq!(
                encode(text),
                format!("=?base64?{}?=", BASE64_STANDARD.encode(text))
            );
        }
    }

    /// Generation supports primitives, skips absent/complex values and applies caps.
    #[test]
    fn primitive_generation_and_encoded_limits_are_enforced() {
        let schema = json!({"properties":{"text":{"type":"string","x-mcp-header":"Text"},"n":{"type":"integer","x-mcp-header":"N"},"flag":{"type":"boolean","x-mcp-header":"Flag"},"absent":{"type":"string","x-mcp-header":"Absent"},"complex":{"type":"string","x-mcp-header":"Complex"}}});
        let annotations = annotations(&schema).unwrap();
        let headers = generate(
            &annotations,
            &json!({"text":"","n":-2,"flag":false,"complex":{}}),
        )
        .unwrap();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[&HeaderName::from_static("mcp-param-text")], "");
        assert_eq!(headers[&HeaderName::from_static("mcp-param-n")], "-2");
        assert_eq!(headers[&HeaderName::from_static("mcp-param-flag")], "false");
        let error = generate(&annotations, &json!({"text":"é".repeat(4_096)})).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
    }
}
