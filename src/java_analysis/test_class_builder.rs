//! Builds small, valid Java class files and archives for tests, so no JDK is needed.
//!
//! Shared by `tests/java_analysis_test.rs` (included by `#[path]`) and by the unit tests
//! of `src/java_analysis.rs` and `src/mcp_server/tools_java.rs`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::Write;

/// Builder for one class file: constant pool, members and a few attributes.
pub struct ClassBuilder {
    pool: Vec<u8>,
    slots: u16,
    index: HashMap<Vec<u8>, u16>,
    major: u16,
    minor: u16,
    access: u16,
    this_class: u16,
    super_class: u16,
    interfaces: Vec<u16>,
    fields: Vec<(u16, u16, u16, Vec<u8>)>,
    methods: Vec<(u16, u16, u16, Vec<u8>)>,
    attributes: Vec<u8>,
    attribute_count: u16,
}

impl ClassBuilder {
    /// `name` uses slashes (`com/example/Hello`).
    pub fn new(name: &str) -> Self {
        let mut builder = Self {
            pool: Vec::new(),
            slots: 0,
            index: HashMap::new(),
            major: 52,
            minor: 0,
            access: 0x0021,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
            attribute_count: 0,
        };
        builder.this_class = builder.class(name);
        builder.super_class = builder.class("java/lang/Object");
        builder
    }

    pub fn major(mut self, major: u16) -> Self {
        self.major = major;
        self
    }

    pub fn access(mut self, access: u16) -> Self {
        self.access = access;
        self
    }

    pub fn super_class(mut self, name: &str) -> Self {
        self.super_class = self.class(name);
        self
    }

    pub fn interface(mut self, name: &str) -> Self {
        let index = self.class(name);
        self.interfaces.push(index);
        self
    }

    pub fn field(mut self, name: &str, descriptor: &str, access: u16) -> Self {
        let (n, d) = (self.utf8(name), self.utf8(descriptor));
        self.fields.push((access, n, d, Vec::new()));
        self
    }

    pub fn method(mut self, name: &str, descriptor: &str, access: u16) -> Self {
        let (n, d) = (self.utf8(name), self.utf8(descriptor));
        self.methods.push((access, n, d, Vec::new()));
        self
    }

    /// A method with a `Code` attribute (`max_locals`) and a `throws` clause.
    pub fn method_with_code(
        mut self,
        name: &str,
        descriptor: &str,
        access: u16,
        max_locals: u16,
        throws: &[&str],
    ) -> Self {
        let (n, d) = (self.utf8(name), self.utf8(descriptor));
        let mut attrs = Vec::new();
        let code = self.utf8("Code");
        attrs.extend(code.to_be_bytes());
        // max_stack, max_locals, code_length=1 (return), code, exception table 0, attrs 0
        let body: Vec<u8> = [
            &1u16.to_be_bytes()[..],
            &max_locals.to_be_bytes(),
            &1u32.to_be_bytes(),
            &[0xb1],
            &0u16.to_be_bytes(),
            &0u16.to_be_bytes(),
        ]
        .concat();
        attrs.extend((body.len() as u32).to_be_bytes());
        attrs.extend(body);
        let mut count = 1u16;
        if !throws.is_empty() {
            count += 1;
            let exceptions = self.utf8("Exceptions");
            attrs.extend(exceptions.to_be_bytes());
            attrs.extend(((2 + 2 * throws.len()) as u32).to_be_bytes());
            attrs.extend((throws.len() as u16).to_be_bytes());
            for t in throws {
                let c = self.class(t);
                attrs.extend(c.to_be_bytes());
            }
        }
        let mut all = count.to_be_bytes().to_vec();
        all.extend(attrs);
        self.methods.push((access, n, d, all));
        self
    }

    /// Adds a `Methodref` to the constant pool (an API this class calls).
    pub fn calls(mut self, owner: &str, name: &str, descriptor: &str) -> Self {
        self.entry(10, owner, name, descriptor);
        self
    }

    /// Adds a `Class` reference to the constant pool.
    pub fn refers_to(mut self, name: &str) -> Self {
        self.class(name);
        self
    }

    pub fn string_constant(mut self, text: &str) -> Self {
        let s = self.utf8(text);
        self.add(vec![8, (s >> 8) as u8, s as u8]);
        self
    }

    /// Adds a long constant, which occupies two pool slots.
    pub fn long_constant(mut self, value: i64) -> Self {
        let mut entry = vec![5];
        entry.extend(value.to_be_bytes());
        self.add(entry);
        self.slots += 1;
        self
    }

    pub fn source_file(mut self, name: &str) -> Self {
        let attr = self.utf8("SourceFile");
        let value = self.utf8(name);
        self.attributes.extend(attr.to_be_bytes());
        self.attributes.extend(2u32.to_be_bytes());
        self.attributes.extend(value.to_be_bytes());
        self.attribute_count += 1;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = vec![0xCA, 0xFE, 0xBA, 0xBE];
        out.extend(self.minor.to_be_bytes());
        out.extend(self.major.to_be_bytes());
        out.extend((self.slots + 1).to_be_bytes());
        out.extend(&self.pool);
        out.extend(self.access.to_be_bytes());
        out.extend(self.this_class.to_be_bytes());
        out.extend(self.super_class.to_be_bytes());
        out.extend((self.interfaces.len() as u16).to_be_bytes());
        for i in &self.interfaces {
            out.extend(i.to_be_bytes());
        }
        for members in [&self.fields, &self.methods] {
            out.extend((members.len() as u16).to_be_bytes());
            for (access, name, descriptor, attrs) in members {
                out.extend(access.to_be_bytes());
                out.extend(name.to_be_bytes());
                out.extend(descriptor.to_be_bytes());
                if attrs.is_empty() {
                    out.extend(0u16.to_be_bytes());
                } else {
                    out.extend(attrs);
                }
            }
        }
        out.extend(self.attribute_count.to_be_bytes());
        out.extend(&self.attributes);
        out
    }

    fn add(&mut self, entry: Vec<u8>) -> u16 {
        if let Some(index) = self.index.get(&entry) {
            return *index;
        }
        self.slots += 1;
        let index = self.slots;
        self.pool.extend(&entry);
        self.index.insert(entry, index);
        index
    }

    fn utf8(&mut self, text: &str) -> u16 {
        let mut entry = vec![1];
        entry.extend((text.len() as u16).to_be_bytes());
        entry.extend(text.as_bytes());
        self.add(entry)
    }

    fn class(&mut self, name: &str) -> u16 {
        let n = self.utf8(name);
        self.add(vec![7, (n >> 8) as u8, n as u8])
    }

    fn entry(&mut self, tag: u8, owner: &str, name: &str, descriptor: &str) -> u16 {
        let class = self.class(owner);
        let n = self.utf8(name);
        let d = self.utf8(descriptor);
        let nat = self.add(vec![12, (n >> 8) as u8, n as u8, (d >> 8) as u8, d as u8]);
        self.add(vec![
            tag,
            (class >> 8) as u8,
            class as u8,
            (nat >> 8) as u8,
            nat as u8,
        ])
    }
}

/// A minimal valid class with the given slash-separated name.
pub fn minimal_class(name: &str) -> Vec<u8> {
    ClassBuilder::new(name).build()
}

/// A class that runs commands: the shape of a dropper's launcher.
pub fn runtime_exec_class(name: &str) -> Vec<u8> {
    ClassBuilder::new(name)
        .calls("java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;")
        .calls(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        )
        .method("run", "()V", 0x0001)
        .build()
}

/// Writes a zip archive from `(name, bytes)` pairs.
pub fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        for (name, data) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    cursor.into_inner()
}

/// Android binary XML for a manifest, built from `(tag, attrs)` events.
///
/// `events`: `Some((tag, attrs))` opens an element, `None` closes the last one. Attribute
/// values are `Av::Str`, `Av::Int` or `Av::Bool`; names without a namespace prefix are
/// written as `android:` attributes except `package`.
pub enum Av {
    Str(&'static str),
    Int(u32),
    Bool(bool),
}

/// One event for [`axml`]: `Some((tag, attributes))` opens an element, `None` closes one.
pub type AxmlEvent = Option<(&'static str, Vec<(&'static str, Av)>)>;

pub fn axml(events: &[AxmlEvent]) -> Vec<u8> {
    let mut strings: Vec<String> = Vec::new();
    let intern = |s: &str, strings: &mut Vec<String>| -> u32 {
        if let Some(p) = strings.iter().position(|x| x == s) {
            return p as u32;
        }
        strings.push(s.to_string());
        (strings.len() - 1) as u32
    };
    let ns_uri = intern("http://schemas.android.com/apk/res/android", &mut strings);
    let ns_prefix = intern("android", &mut strings);
    let mut body = Vec::new();
    // start namespace
    let chunk = |ty: u16, payload: Vec<u8>| -> Vec<u8> {
        let mut c = Vec::new();
        c.extend(ty.to_le_bytes());
        c.extend(16u16.to_le_bytes());
        c.extend(((16 + payload.len()) as u32).to_le_bytes());
        c.extend(1u32.to_le_bytes()); // line
        c.extend(0xFFFF_FFFFu32.to_le_bytes()); // comment
        c.extend(payload);
        c
    };
    let mut p = Vec::new();
    p.extend(ns_prefix.to_le_bytes());
    p.extend(ns_uri.to_le_bytes());
    body.extend(chunk(0x0100, p));
    let mut open: Vec<u32> = Vec::new();
    for event in events {
        match event {
            Some((tag, attrs)) => {
                let tag_index = intern(tag, &mut strings);
                open.push(tag_index);
                let mut p = Vec::new();
                p.extend(0xFFFF_FFFFu32.to_le_bytes()); // ns
                p.extend(tag_index.to_le_bytes());
                p.extend(20u16.to_le_bytes());
                p.extend(20u16.to_le_bytes());
                p.extend((attrs.len() as u16).to_le_bytes());
                p.extend([0u8; 6]);
                for (name, value) in attrs {
                    let name_index = intern(name, &mut strings);
                    let ns = if *name == "package" {
                        0xFFFF_FFFF
                    } else {
                        ns_uri
                    };
                    p.extend(ns.to_le_bytes());
                    p.extend(name_index.to_le_bytes());
                    match value {
                        Av::Str(s) => {
                            let v = intern(s, &mut strings);
                            p.extend(v.to_le_bytes());
                            p.extend(8u16.to_le_bytes());
                            p.extend([0, 0x03]);
                            p.extend(v.to_le_bytes());
                        }
                        Av::Int(n) => {
                            p.extend(0xFFFF_FFFFu32.to_le_bytes());
                            p.extend(8u16.to_le_bytes());
                            p.extend([0, 0x10]);
                            p.extend(n.to_le_bytes());
                        }
                        Av::Bool(b) => {
                            p.extend(0xFFFF_FFFFu32.to_le_bytes());
                            p.extend(8u16.to_le_bytes());
                            p.extend([0, 0x12]);
                            p.extend((if *b { 0xFFFF_FFFFu32 } else { 0 }).to_le_bytes());
                        }
                    }
                }
                body.extend(chunk(0x0102, p));
            }
            None => {
                let tag_index = open.pop().expect("balanced events");
                let mut p = Vec::new();
                p.extend(0xFFFF_FFFFu32.to_le_bytes());
                p.extend(tag_index.to_le_bytes());
                body.extend(chunk(0x0103, p));
            }
        }
    }
    let mut p = Vec::new();
    p.extend(ns_prefix.to_le_bytes());
    p.extend(ns_uri.to_le_bytes());
    body.extend(chunk(0x0101, p));

    // UTF-16 string pool
    let mut pool_data = Vec::new();
    let mut offsets = Vec::new();
    for s in &strings {
        offsets.push(pool_data.len() as u32);
        let units: Vec<u16> = s.encode_utf16().collect();
        pool_data.extend((units.len() as u16).to_le_bytes());
        for u in units {
            pool_data.extend(u.to_le_bytes());
        }
        pool_data.extend(0u16.to_le_bytes());
    }
    while pool_data.len() % 4 != 0 {
        pool_data.push(0);
    }
    let header = 28usize;
    let strings_start = header + offsets.len() * 4;
    let mut pool = Vec::new();
    pool.extend(0x0001u16.to_le_bytes());
    pool.extend((header as u16).to_le_bytes());
    pool.extend(((strings_start + pool_data.len()) as u32).to_le_bytes());
    pool.extend((strings.len() as u32).to_le_bytes());
    pool.extend(0u32.to_le_bytes());
    pool.extend(0u32.to_le_bytes()); // flags: UTF-16
    pool.extend((strings_start as u32).to_le_bytes());
    pool.extend(0u32.to_le_bytes());
    for o in offsets {
        pool.extend(o.to_le_bytes());
    }
    pool.extend(pool_data);

    let mut out = Vec::new();
    out.extend(0x0003u16.to_le_bytes());
    out.extend(8u16.to_le_bytes());
    out.extend(((8 + pool.len() + body.len()) as u32).to_le_bytes());
    out.extend(pool);
    out.extend(body);
    out
}
