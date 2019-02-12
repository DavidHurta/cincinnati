extern crate actix_web;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_json;
extern crate url;

mod errors;
pub use errors::GraphError;

use actix_web::http::header;
use std::collections::HashSet;
use url::form_urlencoded;

/// Strip all but one leading slash and all trailing slashes
pub fn parse_path_prefix(path_prefix: &str) -> String {
    format!("/{}", path_prefix.to_string().trim_matches('/'))
}

/// Parse a comma-separated set of client parameters keys.
pub fn parse_params_set(params: &str) -> HashSet<String> {
    params
        .split(',')
        .filter_map(|key| {
            let trimmed = key.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .collect()
}

/// Make sure `query` string contains all `params` keys.
pub fn ensure_query_params(
    required_params: &HashSet<String>,
    query: &str,
) -> Result<(), GraphError> {
    // No mandatory parameters, always fine.
    if required_params.is_empty() {
        return Ok(());
    }

    // Extract and de-duplicate keys from input query.
    let query_keys: HashSet<String> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .map(|(k, _)| k)
        .collect();

    // Make sure all mandatory parameters are present.
    if !required_params.is_subset(&query_keys) {
        return Err(GraphError::MissingParams);
    }

    Ok(())
}

/// Make sure client requested the relevant content type.
pub fn ensure_content_type(
    headers: &actix_web::http::HeaderMap,
    content_type: &'static str,
) -> Result<(), GraphError> {
    let content_json = header::HeaderValue::from_static(content_type);

    if !headers
        .get(header::ACCEPT)
        .map(|accept| accept == content_json)
        .unwrap_or(false)
    {
        Err(GraphError::InvalidContentType)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path_prefix() {
        assert_eq!(parse_path_prefix("//a/b/c//"), "/a/b/c");
        assert_eq!(parse_path_prefix("/a/b/c/"), "/a/b/c");
        assert_eq!(parse_path_prefix("/a/b/c"), "/a/b/c");
        assert_eq!(parse_path_prefix("a/b/c"), "/a/b/c");
    }

    #[test]
    fn test_parse_params_set() {
        assert_eq!(parse_params_set(""), HashSet::new());

        let basic = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(parse_params_set("a,b,c"), basic.into_iter().collect());

        let dedup = vec!["a".to_string(), "b".to_string()];
        assert_eq!(parse_params_set("a,b,a"), dedup.into_iter().collect());

        let trimmed = vec!["foo".to_string(), "bar".to_string()];
        assert_eq!(
            parse_params_set("foo , , bar"),
            trimmed.into_iter().collect()
        );
    }

    #[test]
    fn test_ensure_query_params() {
        let empty = HashSet::new();
        ensure_query_params(&empty, "").unwrap();
        ensure_query_params(&empty, "a=b").unwrap();

        let simple = vec!["a".to_string()].into_iter().collect();
        ensure_query_params(&simple, "a=b").unwrap();
        ensure_query_params(&simple, "a=b&a=c").unwrap();
        ensure_query_params(&simple, "").unwrap_err();
        ensure_query_params(&simple, "c=d").unwrap_err();
    }

}
