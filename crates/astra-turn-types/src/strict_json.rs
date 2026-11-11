use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::fmt;

/// Parse JSON while rejecting duplicate object keys at every nesting level.
/// This must run on raw bytes before conversion to `serde_json::Value`.
pub fn parse_unique_json(raw: &[u8]) -> Result<Value, serde_json::Error> {
    struct StrictValue(Value);

    impl<'de> Deserialize<'de> for StrictValue {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct StrictValueVisitor;
            impl<'de> Visitor<'de> for StrictValueVisitor {
                type Value = StrictValue;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("JSON without duplicate object keys")
                }

                fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                    Ok(StrictValue(Value::Bool(value)))
                }

                fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                    Ok(StrictValue(Value::Number(value.into())))
                }

                fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                    Ok(StrictValue(Value::Number(value.into())))
                }

                fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    serde_json::Number::from_f64(value)
                        .map(|number| StrictValue(Value::Number(number)))
                        .ok_or_else(|| E::custom("non-finite JSON number"))
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                    Ok(StrictValue(Value::String(value.to_string())))
                }

                fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                    Ok(StrictValue(Value::String(value)))
                }

                fn visit_none<E>(self) -> Result<Self::Value, E> {
                    Ok(StrictValue(Value::Null))
                }

                fn visit_unit<E>(self) -> Result<Self::Value, E> {
                    Ok(StrictValue(Value::Null))
                }

                fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut values = Vec::new();
                    while let Some(StrictValue(value)) = sequence.next_element()? {
                        values.push(value);
                    }
                    Ok(StrictValue(Value::Array(values)))
                }

                fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut values = Map::new();
                    while let Some(key) = access.next_key::<String>()? {
                        if values.contains_key(&key) {
                            return Err(de::Error::custom("duplicate JSON object key"));
                        }
                        let StrictValue(value) = access.next_value()?;
                        values.insert(key, value);
                    }
                    Ok(StrictValue(Value::Object(values)))
                }
            }

            deserializer.deserialize_any(StrictValueVisitor)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let StrictValue(value) = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}
