// Independent encoding generator: does not call production address helpers.
pub fn encodings(octets: [u8; 4]) -> Vec<String> {
    let components = octets.map(|n| {
        vec![
            n.to_string(),
            format!("0{n}"),
            format!("0{n:o}"),
            format!("0x{n:x}"),
            format!("0X{n:X}"),
        ]
    });
    let mut out = Vec::new();
    for a in &components[0] {
        for b in &components[1] {
            for c in &components[2] {
                for d in &components[3] {
                    out.push(format!("{a}.{b}.{c}.{d}"));
                }
            }
        }
    }
    let [a, b, c, d] = octets;
    let n = u32::from_be_bytes(octets);
    let canonical = format!("{a}.{b}.{c}.{d}");
    out.extend([
        n.to_string(),
        format!("0x{n:x}"),
        format!("0X{n:X}"),
        format!("0{n:o}"),
        format!("{a}.{}", n & 0xffffff),
        format!("{a}.{b}.{}", n & 0xffff),
    ]);
    for alias in [
        format!("::ffff:{canonical}"),
        format!("::{canonical}"),
        format!("::FFFF:{:x}:{:x}", n >> 16, n & 65535),
        format!("[{canonical}]"),
        format!("{canonical}%eth0"),
        format!("{canonical}."),
        format!("user@{canonical}"),
        format!("{canonical}:80"),
        format!(" {canonical}"),
        format!("{canonical}\t"),
        format!("{canonical}\r\n"),
        canonical.replace('.', "\u{ff0e}"),
        canonical.replace('1', "\u{ff11}"),
        format!("{canonical}\0"),
        format!("{canonical}{}", "a".repeat(254)),
    ] {
        out.push(alias);
    }
    out.sort();
    out.dedup();
    out
}
pub const DENIED: &[[u8; 4]] = &[
    [0, 0, 0, 1],
    [10, 0, 0, 1],
    [100, 64, 0, 1],
    [127, 0, 0, 1],
    [169, 254, 169, 254],
    [172, 16, 0, 1],
    [192, 0, 0, 9],
    [192, 0, 2, 1],
    [192, 31, 196, 1],
    [192, 52, 193, 1],
    [192, 88, 99, 1],
    [192, 168, 0, 1],
    [192, 175, 48, 1],
    [198, 18, 0, 1],
    [198, 51, 100, 1],
    [203, 0, 113, 1],
    [224, 0, 0, 1],
    [240, 0, 0, 1],
    [255, 255, 255, 255],
    [168, 63, 129, 16],
    [147, 75, 207, 207],
    [192, 80, 8, 124],
];
