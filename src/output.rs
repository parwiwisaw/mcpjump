//! Rendering results and errors as JSON or escaped text.

use comfy_table::{Table, presets};
use serde_json::{Map, Value, json};

use crate::config::model::OutputFormat;
use crate::error::{Error, ErrorKind};

/// Renders a command's result for stdout, ending in a newline. JSON is the
/// contract; text is a generic human layout of the same value.
pub(crate) fn render(result: &Value, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => format!("{result}\n"),
        OutputFormat::Text => format!("{}\n", escape(&text_of(result))),
    }
}

/// Renders an error for stderr, ending in a newline.
pub(crate) fn render_error(error: &Error, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => {
            let mut body = Map::new();
            body.insert("kind".into(), error.kind().as_str().into());
            body.insert("message".into(), error.message().into());
            if let Some(path) = error.path() {
                body.insert("path".into(), path.into());
            }
            if error.kind() == ErrorKind::DeliveryUnknown {
                body.insert("execution".into(), "unknown".into());
            }
            format!("{}\n", json!({ "error": body }))
        }
        OutputFormat::Text => format!("error: {}\n", escape(error.message())),
    }
}

/// Renders a warning for stderr, ending in a newline.
pub(crate) fn render_warning(message: &str, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => format!("{}\n", json!({ "warning": { "message": message } })),
        OutputFormat::Text => format!("warning: {}\n", escape(message)),
    }
}

/// Renders a notice for stderr, ending in a newline: `text` escaped, or
/// `value` as one JSON line.
pub(crate) fn render_notice(text: &str, value: &Value, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => format!("{value}\n"),
        OutputFormat::Text => format!("{}\n", escape(text)),
    }
}

/// Generic text layout: an array of objects is a table, an object is one
/// `key: value` line per field, and anything else is its scalar text.
fn text_of(value: &Value) -> String {
    match value {
        Value::Array(rows) => table_of(rows),
        Value::Object(fields) => fields
            .iter()
            .map(|(key, field)| format!("{key}: {}", cell(field)))
            .collect::<Vec<_>>()
            .join("\n"),
        other => cell(other),
    }
}

/// A table whose columns are the first row's keys. An empty array is empty text.
fn table_of(rows: &[Value]) -> String {
    let columns: Vec<&String> = rows
        .first()
        .and_then(Value::as_object)
        .map(|first| first.keys().collect())
        .unwrap_or_default();
    if columns.is_empty() {
        return rows.iter().map(cell).collect::<Vec<_>>().join("\n");
    }
    let mut table = Table::new();
    table.load_style(presets::NOTHING);
    table.set_header(columns.iter().map(|column| column.to_uppercase()));
    for row in rows {
        table.add_row(columns.iter().map(|column| {
            row.get(column.as_str())
                .map_or_else(|| "-".to_owned(), cell)
        }));
    }
    for column in table.column_iter_mut() {
        column.set_padding((0, 2));
    }
    table.trim_fmt()
}

fn cell(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "-".to_owned(),
        other => other.to_string(),
    }
}

/// Escapes control characters except newline and tab, so server-supplied text
/// cannot drive the terminal.
pub(crate) fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            escaped.extend(c.escape_unicode());
        } else {
            escaped.push(c);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(json: &Value) -> String {
        render(json, OutputFormat::Text)
    }

    #[test]
    fn json_is_compact_with_a_newline() {
        assert_eq!(
            render(&json!({"a": [1, 2]}), OutputFormat::Json),
            "{\"a\":[1,2]}\n"
        );
    }

    #[test]
    fn objects_render_as_key_value_lines() {
        assert_eq!(
            text(&json!({"a": "x", "b": null, "c": 3, "d": {"k": "v"}})),
            "a: x\nb: -\nc: 3\nd: {\"k\":\"v\"}\n"
        );
    }

    #[test]
    fn arrays_of_objects_render_as_tables() {
        let rendered = text(&json!([{"name": "a", "url": "u"}, {"name": "b"}]));
        let lines: Vec<&str> = rendered.lines().map(str::trim_end).collect();
        assert_eq!(lines, ["NAME  URL", "a     u", "b     -"]);
    }

    #[test]
    fn other_arrays_and_scalars_render_as_lines() {
        assert_eq!(text(&json!([])), "\n");
        assert_eq!(text(&json!(["a", true])), "a\ntrue\n");
        assert_eq!(text(&json!("plain")), "plain\n");
    }

    #[test]
    fn text_escapes_control_characters_except_newline_and_tab() {
        assert_eq!(
            escape("a\u{1b}[31m\u{7f}\u{9b}\n\tb"),
            "a\\u{1b}[31m\\u{7f}\\u{9b}\n\tb"
        );
        assert_eq!(text(&json!("x\u{7}")), "x\\u{7}\n");
    }

    #[test]
    fn errors_render_as_json_with_optional_path() {
        let error = Error::new(ErrorKind::InvalidUrl, "bad");
        assert_eq!(
            render_error(&error, OutputFormat::Json),
            "{\"error\":{\"kind\":\"invalid_url\",\"message\":\"bad\"}}\n"
        );
        assert_eq!(
            render_error(&error.with_path("/url"), OutputFormat::Json),
            "{\"error\":{\"kind\":\"invalid_url\",\"message\":\"bad\",\"path\":\"/url\"}}\n"
        );
    }

    #[test]
    fn an_unknown_delivery_says_so() {
        let error = Error::new(ErrorKind::DeliveryUnknown, "lost");
        assert_eq!(
            render_error(&error, OutputFormat::Json),
            "{\"error\":{\"kind\":\"delivery_unknown\",\"message\":\"lost\",\"execution\":\"unknown\"}}\n"
        );
    }

    #[test]
    fn warnings_render_as_json_or_escaped_text() {
        assert_eq!(
            render_warning("w", OutputFormat::Json),
            "{\"warning\":{\"message\":\"w\"}}\n"
        );
        assert_eq!(
            render_warning("w\u{1b}", OutputFormat::Text),
            "warning: w\\u{1b}\n"
        );
    }

    #[test]
    fn errors_render_as_escaped_text() {
        let error = Error::new(ErrorKind::ConfigIo, "no\u{1b}");
        assert_eq!(
            render_error(&error, OutputFormat::Text),
            "error: no\\u{1b}\n"
        );
    }
}
