pub mod code;
pub mod crypto;
pub mod identity;
pub mod link;
pub mod pairing;

pub fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
pub fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
pub mod departure;
pub mod metadata;
pub mod rendezvous;
pub mod stream;

/// ASP.NET REST uses camelCase; signed binary/embedded documents use PascalCase.
/// Normalize only at the HTTP boundary; reject ambiguous duplicate spellings.
pub fn parse_rest<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    fn normalize(value: serde_json::Value, depth: usize) -> anyhow::Result<serde_json::Value> {
        anyhow::ensure!(depth <= 24, "REST document nesting exceeds limit");
        Ok(match value {
            serde_json::Value::Object(fields) => {
                let mut out = serde_json::Map::new();
                for (key, value) in fields {
                    let mut chars = key.chars();
                    let key = chars
                        .next()
                        .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                        .unwrap_or_default();
                    anyhow::ensure!(!out.contains_key(&key), "ambiguous REST field casing");
                    out.insert(key, normalize(value, depth + 1)?);
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(values) => serde_json::Value::Array(
                values
                    .into_iter()
                    .map(|v| normalize(v, depth + 1))
                    .collect::<anyhow::Result<_>>()?,
            ),
            value => value,
        })
    }
    Ok(serde_json::from_value(normalize(
        serde_json::from_slice(bytes)?,
        0,
    )?)?)
}
