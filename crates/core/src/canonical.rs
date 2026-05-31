use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        Value::Object(map) => {
            let mut ordered = Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(child) = map.get(key) {
                    ordered.insert(key.clone(), canonicalize_json(child));
                }
            }
            Value::Object(ordered)
        }
        other => other.clone(),
    }
}

pub fn hash_canonical_json(value: &Value) -> String {
    let canonical = canonicalize_json(value);
    let bytes = serde_json::to_vec(&canonical).expect("canonical JSON should serialize");
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::hash_canonical_json;
    use serde_json::json;

    #[test]
    fn hashes_objects_independent_of_key_order() {
        let left = json!({"b": 1, "a": {"d": true, "c": null}});
        let right = json!({"a": {"c": null, "d": true}, "b": 1});

        assert_eq!(hash_canonical_json(&left), hash_canonical_json(&right));
    }
}
