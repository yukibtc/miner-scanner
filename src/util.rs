pub(crate) fn truncate(s: String, max: usize) -> String {
    let char_count: usize = s.chars().count();

    if char_count <= max {
        s
    } else {
        s.chars().take(max).collect()
    }
}
