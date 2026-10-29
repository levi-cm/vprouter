//! Private bounded JSON decoder. Decoded text and keys live in one initialized,
//! non-growing wiping arena. Serde sees borrowed strings (including escapes and
//! flatten replay); errors never format untrusted input into an allocation.
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
struct Error;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Docker JSON")
    }
}
impl std::error::Error for Error {}
impl de::Error for Error {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy)]
struct Span(usize, usize);
enum Node {
    Null,
    Literal(Span),
    Number(Span),
    String(Span),
    Array(Vec<usize>),
    Object(Vec<(Span, usize)>),
}
struct Document<'a> {
    input: &'a [u8],
    arena: Zeroizing<Vec<u8>>,
    at: usize,
    used: usize,
    nodes: Vec<Node>,
}
pub(super) fn decode<T: DeserializeOwned>(input: &[u8]) -> crate::Result<T> {
    if input.len() > super::LIMIT {
        return Err(crate::Error::TooLarge);
    }
    let mut doc = Document {
        input,
        arena: Zeroizing::new(vec![0; input.len()]),
        at: 0,
        used: 0,
        nodes: Vec::new(),
    };
    let value = (|| {
        let root = doc.value(0)?;
        doc.ws();
        if doc.at != input.len() {
            return Err(Error);
        }
        T::deserialize(Value {
            doc: &doc,
            index: root,
        })
    })();
    value.map_err(|_| crate::Error::DockerProtocol)
}
impl Document<'_> {
    fn ws(&mut self) {
        while self
            .input
            .get(self.at)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.at += 1;
        }
    }
    fn byte(&mut self, wanted: u8) -> Result<()> {
        if self.input.get(self.at) != Some(&wanted) {
            return Err(Error);
        }
        self.at += 1;
        Ok(())
    }
    fn literal(&mut self, text: &[u8]) -> Result<()> {
        if !self.input[self.at..].starts_with(text) {
            return Err(Error);
        }
        self.at += text.len();
        Ok(())
    }
    fn hex4(&mut self) -> Result<u16> {
        let mut n = 0;
        for _ in 0..4 {
            let b = *self.input.get(self.at).ok_or(Error)?;
            self.at += 1;
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(Error),
            };
            n = (n << 4) | u16::from(v);
        }
        Ok(n)
    }
    fn string(&mut self) -> Result<Span> {
        self.byte(b'"')?;
        let begin = self.used;
        loop {
            let b = *self.input.get(self.at).ok_or(Error)?;
            self.at += 1;
            match b {
                b'"' => break,
                0..=31 => return Err(Error),
                b'\\' => {
                    let e = *self.input.get(self.at).ok_or(Error)?;
                    self.at += 1;
                    let decoded = match e {
                        b'"' | b'\\' | b'/' => e,
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'u' => {
                            let first = self.hex4()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                self.byte(b'\\')?;
                                self.byte(b'u')?;
                                let second = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(Error);
                                }
                                0x10000
                                    + ((u32::from(first) - 0xd800) << 10)
                                    + (u32::from(second) - 0xdc00)
                            } else {
                                u32::from(first)
                            };
                            let c = char::from_u32(scalar).ok_or(Error)?;
                            let n = c.len_utf8();
                            let slot = self.arena.get_mut(self.used..self.used + n).ok_or(Error)?;
                            c.encode_utf8(slot);
                            self.used += n;
                            continue;
                        }
                        _ => return Err(Error),
                    };
                    *self.arena.get_mut(self.used).ok_or(Error)? = decoded;
                    self.used += 1;
                }
                _ => {
                    *self.arena.get_mut(self.used).ok_or(Error)? = b;
                    self.used += 1;
                }
            }
        }
        std::str::from_utf8(&self.arena[begin..self.used]).map_err(|_| Error)?;
        Ok(Span(begin, self.used))
    }
    fn value(&mut self, depth: usize) -> Result<usize> {
        if depth >= 128 || self.nodes.len() >= 65536 {
            return Err(Error);
        }
        // Reserve before descending so large nested containers count too.
        let index = self.nodes.len();
        self.nodes.push(Node::Null);
        self.ws();
        let node = match self.input.get(self.at).copied().ok_or(Error)? {
            b'n' => {
                self.literal(b"null")?;
                Node::Null
            }
            b't' => {
                let begin = self.at;
                self.literal(b"true")?;
                Node::Literal(Span(begin, self.at))
            }
            b'f' => {
                let begin = self.at;
                self.literal(b"false")?;
                Node::Literal(Span(begin, self.at))
            }
            b'"' => Node::String(self.string()?),
            b'[' => {
                self.at += 1;
                self.ws();
                let mut values = Vec::new();
                if self.input.get(self.at) != Some(&b']') {
                    loop {
                        values.push(self.value(depth + 1)?);
                        self.ws();
                        if self.input.get(self.at) != Some(&b',') {
                            break;
                        }
                        self.at += 1;
                    }
                }
                self.byte(b']')?;
                Node::Array(values)
            }
            b'{' => {
                self.at += 1;
                self.ws();
                let mut values = Vec::new();
                if self.input.get(self.at) != Some(&b'}') {
                    loop {
                        self.ws();
                        let key = self.string()?;
                        self.ws();
                        self.byte(b':')?;
                        values.push((key, self.value(depth + 1)?));
                        self.ws();
                        if self.input.get(self.at) != Some(&b',') {
                            break;
                        }
                        self.at += 1;
                    }
                }
                self.byte(b'}')?;
                Node::Object(values)
            }
            b'-' | b'0'..=b'9' => {
                let begin = self.at;
                if self.input[self.at] == b'-' {
                    self.at += 1;
                }
                match self.input.get(self.at) {
                    Some(b'0') => self.at += 1,
                    Some(b'1'..=b'9') => {
                        self.at += 1;
                        while self.input.get(self.at).is_some_and(u8::is_ascii_digit) {
                            self.at += 1;
                        }
                    }
                    _ => return Err(Error),
                }
                if self.input.get(self.at) == Some(&b'.') {
                    self.at += 1;
                    let start = self.at;
                    while self.input.get(self.at).is_some_and(u8::is_ascii_digit) {
                        self.at += 1;
                    }
                    if start == self.at {
                        return Err(Error);
                    }
                }
                if self
                    .input
                    .get(self.at)
                    .is_some_and(|b| matches!(b, b'e' | b'E'))
                {
                    self.at += 1;
                    if self
                        .input
                        .get(self.at)
                        .is_some_and(|b| matches!(b, b'+' | b'-'))
                    {
                        self.at += 1;
                    }
                    let start = self.at;
                    while self.input.get(self.at).is_some_and(u8::is_ascii_digit) {
                        self.at += 1;
                    }
                    if start == self.at {
                        return Err(Error);
                    }
                }
                Node::Number(Span(begin, self.at))
            }
            _ => return Err(Error),
        };
        self.nodes[index] = node;
        Ok(index)
    }
    fn text(&self, s: Span) -> &str {
        std::str::from_utf8(&self.arena[s.0..s.1]).expect("validated arena UTF-8")
    }
}
#[derive(Clone, Copy)]
struct Value<'de, 'a> {
    doc: &'de Document<'a>,
    index: usize,
}
impl<'de> de::Deserializer<'de> for Value<'de, '_> {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match &self.doc.nodes[self.index] {
            Node::Null => visitor.visit_unit(),
            Node::Literal(s) => visitor.visit_bool(&self.doc.input[s.0..s.1] == b"true"),
            Node::String(s) => visitor.visit_borrowed_str(self.doc.text(*s)),
            Node::Number(s) => {
                let text = std::str::from_utf8(&self.doc.input[s.0..s.1]).map_err(|_| Error)?;
                if text != "-0" && !text.bytes().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                    if text.starts_with('-') {
                        if let Ok(n) = text.parse::<i64>() {
                            return visitor.visit_i64(n);
                        }
                    } else if let Ok(n) = text.parse::<u64>() {
                        return visitor.visit_u64(n);
                    }
                }
                let n: f64 = text.parse().map_err(|_| Error)?;
                if !n.is_finite() {
                    return Err(Error);
                }
                visitor.visit_f64(n)
            }
            Node::Array(values) => visitor.visit_seq(Sequence {
                doc: self.doc,
                values: values.iter(),
            }),
            Node::Object(values) => visitor.visit_map(Mapping {
                doc: self.doc,
                values: values.iter(),
                pending: None,
            }),
        }
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if matches!(self.doc.nodes[self.index], Node::Null) {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }
    serde::forward_to_deserialize_any! { bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf unit unit_struct seq tuple tuple_struct map struct enum identifier }
}
struct Sequence<'de, 'a> {
    doc: &'de Document<'a>,
    values: std::slice::Iter<'de, usize>,
}
impl<'de> SeqAccess<'de> for Sequence<'de, '_> {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        self.values
            .next()
            .map(|index| {
                seed.deserialize(Value {
                    doc: self.doc,
                    index: *index,
                })
            })
            .transpose()
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.values.len())
    }
}
struct Mapping<'de, 'a> {
    doc: &'de Document<'a>,
    values: std::slice::Iter<'de, (Span, usize)>,
    pending: Option<usize>,
}
impl<'de> MapAccess<'de> for Mapping<'de, '_> {
    type Error = Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.pending.is_some() {
            return Err(Error);
        }
        self.values
            .next()
            .map(|(key, index)| {
                self.pending = Some(*index);
                seed.deserialize(de::value::BorrowedStrDeserializer::<Error>::new(
                    self.doc.text(*key),
                ))
            })
            .transpose()
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(Value {
            doc: self.doc,
            index: self.pending.take().ok_or(Error)?,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.values.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn syntax_unicode_duplicates_and_numeric_shapes_match_closed_json() {
        for input in [
            r#"{"raw":"é🦀","escaped":"\u00e9\ud83e\udd80","nul":"\u0000","all":"\"\\\/\b\f\n\r\t"}"#,
            r#"[null,true,false,0,-0,-1,18446744073709551615,-9223372036854775808,1.25,2e3,-4.5e-4]"#,
            r#"{"a":1,"a":2,"b":[{},[]]}"#,
        ] {
            let actual: serde_json::Value = decode(input.as_bytes()).unwrap();
            let expected: serde_json::Value = serde_json::from_str(input).unwrap();
            assert_eq!(actual, expected);
        }
        for input in [
            "",
            "null null",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "+1",
            "1.",
            "1e",
            "--1",
            "NaN",
            "Infinity",
            "1e999",
            "\"\\uD800\"",
            "\"\\uDC00\"",
            "\"\\uD800\\u0000\"",
            "\"\n\"",
            "\"\\x00\"",
        ] {
            assert!(
                decode::<serde_json::Value>(input.as_bytes()).is_err(),
                "accepted malformed input"
            );
            assert!(serde_json::from_str::<serde_json::Value>(input).is_err());
        }
        assert!(decode::<serde_json::Value>(b"\"\xff\"").is_err());
        assert!(
            decode::<serde_json::Value>(
                format!("{}0{}", "[".repeat(129), "]".repeat(129)).as_bytes()
            )
            .is_err()
        );
        assert!(
            decode::<serde_json::Value>(format!("[{}0]", "0,".repeat(65536)).as_bytes()).is_err()
        );
    }
    #[test]
    fn escaped_keys_and_flatten_replay_are_borrowed() {
        #[derive(serde::Deserialize)]
        struct Borrowed<'a> {
            #[serde(borrow, flatten)]
            extra: BTreeMap<&'a str, &'a str>,
        }
        use std::collections::BTreeMap;
        let input = br#"{"\u006bey":"\u0076alue"}"#;
        let mut doc = Document {
            input,
            arena: Zeroizing::new(vec![0; input.len()]),
            at: 0,
            used: 0,
            nodes: Vec::new(),
        };
        let index = doc.value(0).unwrap();
        let value =
            <Borrowed as serde::Deserialize>::deserialize(Value { doc: &doc, index }).unwrap();
        assert_eq!(value.extra.get("key"), Some(&"value"));
        for (k, v) in value.extra {
            let span = doc.arena.as_ptr_range();
            assert!(span.contains(&k.as_ptr()) && span.contains(&v.as_ptr()));
        }
    }
}
