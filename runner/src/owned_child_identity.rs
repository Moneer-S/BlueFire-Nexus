//! Read-only identity parsing for an unreaped child in its own process group.

pub(crate) fn parse(bytes: &[u8], pid: u32, parent: u32) -> Result<(bool, u64), ()> {
    if bytes.len() > 4096 {
        return Err(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    let prefix = format!("{pid} (");
    let fields: Vec<_> = text
        .strip_prefix(&prefix)
        .and_then(|text| text.rsplit_once(") "))
        .ok_or(())?
        .1
        .split_whitespace()
        .collect();
    if fields.len() < 20
        || fields[1] != parent.to_string()
        || fields[2] != pid.to_string()
        || !matches!(
            fields[0],
            "R" | "S" | "D" | "Z" | "T" | "t" | "X" | "x" | "K" | "W" | "P" | "I"
        )
    {
        return Err(());
    }
    let ticks: u64 = fields[19].parse().map_err(|_| ())?;
    if ticks == 0 || ticks.to_string() != fields[19] {
        return Err(());
    }
    Ok((matches!(fields[0], "Z" | "X" | "x"), ticks))
}
