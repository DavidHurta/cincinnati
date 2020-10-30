use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RequestBody {
    /// A brief description of the request body.
    /// This could contain examples of use.
    /// CommonMark syntax MAY be used for rich text representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// REQUIRED. The content of the request body.
    /// The key is a media type or media type range and
    /// the value describes it. For requests that match
    /// multiple keys, only the most specific key is applicable.
    ///  e.g. text/plain overrides text/*
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub content: BTreeMap<String, MediaType>,
    /// Determines if the request body is required in the
    /// request. Defaults to false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
}
