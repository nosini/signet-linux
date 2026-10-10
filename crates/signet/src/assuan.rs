// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{Result, bail};
use std::io::{self, BufRead, Write};
pub fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in bytes {
        match b {
            b'%' | b'\r' | b'\n' => out.extend_from_slice(format!("%{b:02X}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}
pub fn decode(bytes: &[u8], plus: bool) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                bail!("invalid Assuan escape");
            }
            out.push(u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3])?,
                16,
            )?);
            i += 3;
        } else {
            out.push(if plus && bytes[i] == b'+' {
                b' '
            } else {
                bytes[i]
            });
            i += 1;
        }
    }
    Ok(out)
}
pub fn line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if out.is_empty() {
                return Ok(None);
            }
            bail!("unterminated Assuan line");
        }
        let n = available
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(available.len());
        if out.len() + n > 1000 {
            bail!("Assuan line too long");
        }
        out.extend_from_slice(&available[..n]);
        reader.consume(n);
        if out.last() == Some(&b'\n') {
            out.pop();
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            return Ok(Some(out));
        }
    }
}
pub fn data(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for chunk in bytes.chunks(300) {
        writer.write_all(b"D ")?;
        writer.write_all(&escape(chunk))?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}
pub fn inquire(reader: &mut impl BufRead, writer: &mut impl Write) -> Result<Vec<u8>> {
    writer.write_all(b"S INQUIRE_MAXLEN 16384\nINQUIRE CIPHERTEXT\n")?;
    writer.flush()?;
    let mut bytes = Vec::new();
    loop {
        let value = line(reader)?.ok_or_else(|| anyhow::anyhow!("client disconnected"))?;
        if value == b"END" {
            return Ok(bytes);
        }
        if value == b"CAN" {
            bail!("cancelled");
        }
        if let Some(part) = value.strip_prefix(b"D ") {
            bytes.extend(decode(part, false)?);
            if bytes.len() > 16384 {
                bail!("ciphertext too large");
            }
        } else if !value.starts_with(b"#") {
            bail!("unexpected inquiry response");
        }
    }
}
#[derive(Clone, Debug)]
pub enum Sexp {
    Atom(Vec<u8>),
    List(Vec<Sexp>),
}
impl Sexp {
    pub fn atom(value: impl AsRef<[u8]>) -> Self {
        Self::Atom(value.as_ref().to_vec())
    }
    pub fn named(name: &str, value: impl AsRef<[u8]>) -> Self {
        Self::List(vec![Self::atom(name), Self::atom(value)])
    }
    pub fn list(value: Vec<Self>) -> Self {
        Self::List(value)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Atom(bytes) => {
                out.extend_from_slice(format!("{}:", bytes.len()).as_bytes());
                out.extend_from_slice(bytes);
            }
            Self::List(items) => {
                out.push(b'(');
                for item in items {
                    item.write(out);
                }
                out.push(b')');
            }
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        fn parse_one(bytes: &[u8], offset: &mut usize, depth: usize) -> Result<Sexp> {
            if depth > 20 {
                bail!("S-expression nesting too deep");
            }
            if bytes.get(*offset) == Some(&b'(') {
                *offset += 1;
                let mut items = Vec::new();
                while bytes.get(*offset) != Some(&b')') {
                    if *offset >= bytes.len() {
                        bail!("unterminated S-expression");
                    }
                    items.push(parse_one(bytes, offset, depth + 1)?);
                }
                *offset += 1;
                Ok(Sexp::List(items))
            } else {
                let start = *offset;
                while bytes.get(*offset).is_some_and(u8::is_ascii_digit) {
                    *offset += 1;
                }
                if *offset == start || bytes.get(*offset) != Some(&b':') {
                    bail!("invalid S-expression atom");
                }
                let len: usize = std::str::from_utf8(&bytes[start..*offset])?.parse()?;
                *offset += 1;
                let end = offset
                    .checked_add(len)
                    .filter(|&n| n <= bytes.len())
                    .ok_or_else(|| anyhow::anyhow!("truncated S-expression"))?;
                let atom = Sexp::Atom(bytes[*offset..end].to_vec());
                *offset = end;
                Ok(atom)
            }
        }
        let mut offset = 0;
        let result = parse_one(bytes, &mut offset, 0)?;
        if bytes[offset..].iter().any(|&b| b != 0) {
            bail!("trailing S-expression data");
        }
        Ok(result)
    }
    pub fn find(&self, name: &[u8]) -> Option<&[u8]> {
        if let Self::List(items) = self {
            if let [Self::Atom(key), Self::Atom(value)] = items.as_slice()
                && key == name
            {
                return Some(value);
            }
            for item in items {
                if let Some(value) = item.find(name) {
                    return Some(value);
                }
            }
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_roundtrip_and_bounds() {
        let data =
            Sexp::list(vec![Sexp::atom("value"), Sexp::atom([0, b'\n', b'%', 255])]).encode();
        assert_eq!(Sexp::parse(&data).unwrap().encode(), data);
        assert!(Sexp::parse(b"(1000000000:a)").is_err());
        assert!(line(&mut &vec![b'a'; 1001][..]).is_err());
        assert_eq!(
            decode(&escape(&[0, b'%', b'\n', b'\r', 255]), false).unwrap(),
            [0, b'%', b'\n', b'\r', 255]
        );
    }
}
