//! Owned Docker input fields wipe on replacement, partial decode failure and
//! final Drop. Public inventory must explicitly validate before releasing text.
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use std::{borrow::Borrow, cmp::Ordering, collections::BTreeMap, fmt, ops::Deref};
use zeroize::Zeroizing;

pub struct InputString(Zeroizing<String>);
impl InputString {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl From<&str> for InputString {
    fn from(value: &str) -> Self {
        Self(Zeroizing::new(value.to_owned()))
    }
}
impl From<String> for InputString {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}
impl Clone for InputString {
    fn clone(&self) -> Self {
        Self::from(self.as_str())
    }
}
impl Deref for InputString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for InputString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Borrow<str> for InputString {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
impl fmt::Debug for InputString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InputString([redacted])")
    }
}
impl<T: AsRef<str> + ?Sized> PartialEq<T> for InputString {
    fn eq(&self, other: &T) -> bool {
        self.as_str() == other.as_ref()
    }
}
impl Eq for InputString {}
impl PartialOrd for InputString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for InputString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl<'de> Deserialize<'de> for InputString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Text;
        impl Visitor<'_> for Text {
            type Value = InputString;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(InputString::from(v))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(InputString::from(v))
            }
        }
        d.deserialize_string(Text)
    }
}

/// Dynamic scalar payloads stay in stable wiping allocations; Vec/map moves
/// copy only pointers, never the unknown scalar bits into abandoned capacity.
pub enum InputNumber {
    Signed(Box<Zeroizing<i64>>),
    Unsigned(Box<Zeroizing<u64>>),
    Float(Box<Zeroizing<f64>>),
}
impl PartialEq<serde_json::Number> for InputNumber {
    fn eq(&self, other: &serde_json::Number) -> bool {
        match self {
            Self::Signed(v) => !other.is_f64() && other.as_i64() == Some(***v),
            Self::Unsigned(v) => !other.is_f64() && other.as_u64() == Some(***v),
            Self::Float(v) => other.is_f64() && other.as_f64() == Some(***v),
        }
    }
}
pub enum InputValue {
    Null,
    Bool(Box<Zeroizing<bool>>),
    Number(InputNumber),
    String(InputString),
    Array(Vec<InputValue>),
    Object(BTreeMap<InputString, InputValue>),
}
impl InputValue {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}
impl fmt::Debug for InputValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InputValue([redacted])")
    }
}
// Policy constants are public serde_json values. Comparison never copies the
// input text into their ordinary String representation.
impl PartialEq<serde_json::Value> for InputValue {
    fn eq(&self, other: &serde_json::Value) -> bool {
        use serde_json::Value as V;
        match (self, other) {
            (Self::Null, V::Null) => true,
            (Self::Bool(a), V::Bool(b)) => ***a == *b,
            (Self::Number(a), V::Number(b)) => a == b,
            (Self::String(a), V::String(b)) => a == b,
            (Self::Array(a), V::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a == b)
            }
            (Self::Object(a), V::Object(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .all(|(k, v)| b.get(k.as_str()).is_some_and(|b| v == b))
            }
            _ => false,
        }
    }
}
impl<'de> Deserialize<'de> for InputValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Value;
        impl<'de> Visitor<'de> for Value {
            type Value = InputValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(InputValue::Null)
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(InputValue::Bool(Box::new(Zeroizing::new(v))))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(InputValue::Number(InputNumber::Signed(Box::new(
                    Zeroizing::new(v),
                ))))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(InputValue::Number(InputNumber::Unsigned(Box::new(
                    Zeroizing::new(v),
                ))))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                if !v.is_finite() {
                    return Err(E::custom("invalid number"));
                }
                Ok(InputValue::Number(InputNumber::Float(Box::new(
                    Zeroizing::new(v),
                ))))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(InputValue::String(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(InputValue::String(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = a.next_element()? {
                    values.push(v);
                }
                Ok(InputValue::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((k, v)) = a.next_entry()? {
                    values.insert(k, v);
                }
                Ok(InputValue::Object(values))
            }
        }
        d.deserialize_any(Value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dynamic_scalar_comparisons_preserve_integer_float_distinction() {
        for input in [
            "null",
            "true",
            "false",
            "0",
            "-0",
            "1",
            "-1",
            "18446744073709551615",
            "-9223372036854775808",
            "1.0",
            "1e0",
            "-0.1",
            "[]",
            "{}",
            r#"{"x":"\u00e9"}"#,
        ] {
            let ours: InputValue = crate::docker::managed_json::decode(input.as_bytes()).unwrap();
            let old: serde_json::Value = serde_json::from_str(input).unwrap();
            assert_eq!(ours, old);
        }
        let integer: InputValue = crate::docker::managed_json::decode(b"1").unwrap();
        let float: InputValue = crate::docker::managed_json::decode(b"1.0").unwrap();
        assert_ne!(integer, serde_json::json!(1.0));
        assert_ne!(float, serde_json::json!(1));
    }
}
