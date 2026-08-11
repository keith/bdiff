use std::time::Duration;

use similar::{Algorithm, DiffTag, TextDiff};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineKind {
    Equal,
    Delete,
    Insert,
    Replace,
}

#[derive(Clone, Debug)]
pub struct DiffLine {
    pub left: String,
    pub right: String,
    pub kind: LineKind,
}

#[derive(Clone, Debug)]
pub struct DiffView {
    pub lines: Vec<DiffLine>,
    pub changed_lines: Vec<usize>,
    pub identical: bool,
    pub incomplete: bool,
}

impl DiffView {
    pub fn new(left: &str, right: &str) -> Self {
        let left_lines: Vec<&str> = left.lines().collect();
        let right_lines: Vec<&str> = right.lines().collect();
        let mut config = TextDiff::configure();
        config
            .algorithm(Algorithm::Patience)
            .timeout(Duration::from_secs(2));
        let diff = config.diff_slices(&left_lines, &right_lines);
        let mut lines = Vec::new();

        for operation in diff.ops() {
            let old = &left_lines[operation.old_range()];
            let new = &right_lines[operation.new_range()];
            match operation.tag() {
                DiffTag::Equal => {
                    for (left, right) in old.iter().zip(new) {
                        lines.push(DiffLine {
                            left: (*left).to_owned(),
                            right: (*right).to_owned(),
                            kind: LineKind::Equal,
                        });
                    }
                }
                DiffTag::Delete => {
                    for left in old {
                        lines.push(DiffLine {
                            left: (*left).to_owned(),
                            right: String::new(),
                            kind: LineKind::Delete,
                        });
                    }
                }
                DiffTag::Insert => {
                    for right in new {
                        lines.push(DiffLine {
                            left: String::new(),
                            right: (*right).to_owned(),
                            kind: LineKind::Insert,
                        });
                    }
                }
                DiffTag::Replace => {
                    let count = old.len().max(new.len());
                    for index in 0..count {
                        lines.push(DiffLine {
                            left: old.get(index).copied().unwrap_or_default().to_owned(),
                            right: new.get(index).copied().unwrap_or_default().to_owned(),
                            kind: LineKind::Replace,
                        });
                    }
                }
            }
        }

        // Both empty outputs still need a renderable row.
        if lines.is_empty() {
            lines.push(DiffLine {
                left: String::new(),
                right: String::new(),
                kind: LineKind::Equal,
            });
        }
        let changed_lines = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| (line.kind != LineKind::Equal).then_some(index))
            .collect::<Vec<_>>();
        Self {
            identical: changed_lines.is_empty(),
            incomplete: output_is_incomplete(left) || output_is_incomplete(right),
            lines,
            changed_lines,
        }
    }

    pub fn unified(&self) -> String {
        let mut output = String::new();
        for line in &self.lines {
            match line.kind {
                LineKind::Equal => {
                    output.push_str("  ");
                    output.push_str(&line.left);
                    output.push('\n');
                }
                LineKind::Delete => {
                    output.push_str("- ");
                    output.push_str(&line.left);
                    output.push('\n');
                }
                LineKind::Insert => {
                    output.push_str("+ ");
                    output.push_str(&line.right);
                    output.push('\n');
                }
                LineKind::Replace => {
                    if !line.left.is_empty() {
                        output.push_str("- ");
                        output.push_str(&line.left);
                        output.push('\n');
                    }
                    if !line.right.is_empty() {
                        output.push_str("+ ");
                        output.push_str(&line.right);
                        output.push('\n');
                    }
                }
            }
        }
        output
    }
}

fn output_is_incomplete(output: &str) -> bool {
    output.lines().any(|line| {
        line.starts_with("[tool unavailable:")
            || line.starts_with("[failed")
            || line.starts_with("[tool timed out")
            || line.starts_with("[tool cancelled")
            || line.starts_with("[output limit reached;")
            || line.starts_with("[output truncated")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_replacements_side_by_side() {
        let view = DiffView::new("same\nold\ntail\n", "same\nnew\ntail\n");
        assert_eq!(view.lines.len(), 3);
        assert_eq!(view.lines[1].left, "old");
        assert_eq!(view.lines[1].right, "new");
        assert_eq!(view.lines[1].kind, LineKind::Replace);
        assert_eq!(view.changed_lines, vec![1]);
    }

    #[test]
    fn marks_limited_output_as_incomplete() {
        let view = DiffView::new(
            "same\n[output truncated after 10 bytes]",
            "same\n[output truncated after 10 bytes]",
        );
        assert!(view.identical);
        assert!(view.incomplete);
    }
}
