use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::artifact::{Analysis, Artifact, Comparison, FormatKind};
use crate::diff::DiffView;

const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SPARSE_XXD_OUTPUT_BYTES: usize = 128 * 1024 * 1024;
const XXD_ROW_BYTES: u64 = 16;
const XXD_CONTEXT_ROWS: u64 = 3;

#[derive(Clone, Copy, Debug)]
enum InternalPass {
    Overview,
}

#[derive(Clone, Debug)]
struct CommandSpec {
    programs: Vec<String>,
    args: Vec<String>,
    capture_stderr: bool,
}

#[derive(Clone, Debug)]
enum Runner {
    Internal(InternalPass),
    Command(CommandSpec),
    SparseXxd,
}

#[derive(Clone, Debug)]
pub struct PassSpec {
    pub id: String,
    pub title: String,
    pub description: String,
    lazy: bool,
    formats: Vec<FormatKind>,
    runner: Runner,
}

impl PassSpec {
    pub fn applies_to_kind(&self, kind: FormatKind) -> bool {
        self.formats.is_empty() || self.formats.contains(&kind)
    }

    pub fn applies_to(&self, comparison: &Comparison) -> bool {
        comparison
            .left
            .iter()
            .chain(comparison.right.iter())
            .any(|artifact| self.applies_to_kind(artifact.kind))
    }

    pub fn is_lazy(&self) -> bool {
        self.lazy
    }
}

#[derive(Clone, Debug)]
pub struct PassRegistry {
    pub passes: Vec<PassSpec>,
}

impl PassRegistry {
    pub fn builtin() -> Self {
        use FormatKind::{Archive, Elf, FatMachO, MachO, Pe};

        let mut passes = vec![
            internal(
                "overview",
                "Overview",
                "Detected format, SHA-256, size, container entries, and attached metadata",
                &[],
                InternalPass::Overview,
            ),
            command(
                "ar-t",
                "ar t",
                "Archive member order",
                &[Archive],
                "ar",
                &["t", "{path}"],
                true,
            ),
            command(
                "ar-tv",
                "ar tv",
                "Archive member metadata",
                &[Archive],
                "ar",
                &["tv", "{path}"],
                true,
            ),
            command(
                "lipo-info",
                "lipo -info",
                "Fat Mach-O architecture summary",
                &[FatMachO],
                "lipo",
                &["-info", "{path}"],
                true,
            ),
            command(
                "lipo-detailed-info",
                "lipo -detailed_info",
                "Fat Mach-O slice offsets, sizes, alignment, and CPU subtypes",
                &[FatMachO],
                "lipo",
                &["-detailed_info", "{path}"],
                true,
            ),
            command(
                "otool-fat-headers",
                "otool -fV",
                "Fat Mach-O headers",
                &[FatMachO],
                "otool",
                &["-fV", "{path}"],
                true,
            ),
            command(
                "otool-hv",
                "otool -hv",
                "Mach-O header",
                &[MachO],
                "otool",
                &["-hv", "{path}"],
                true,
            ),
            command(
                "readelf-h",
                "readelf -h",
                "ELF file header",
                &[Elf],
                "readelf",
                &["-h", "{path}"],
                true,
            ),
            command(
                "pe-headers",
                "llvm-readobj (PE headers)",
                "Portable Executable and COFF headers",
                &[Pe],
                "llvm-readobj",
                &["--file-headers", "{path}"],
                true,
            ),
            command(
                "otool-L",
                "otool -L",
                "Mach-O linked libraries",
                &[MachO],
                "otool",
                &["-L", "{path}"],
                true,
            ),
            command(
                "elf-dynamic",
                "readelf -dW",
                "ELF dynamic section and dependencies",
                &[Elf],
                "readelf",
                &["-dW", "{path}"],
                true,
            ),
            command(
                "pe-imports",
                "llvm-readobj (PE imports)",
                "PE imported libraries and symbols",
                &[Pe],
                "llvm-readobj",
                &["--coff-imports", "{path}"],
                true,
            ),
            command(
                "pe-sections",
                "llvm-readobj (PE sections)",
                "PE/COFF section table",
                &[Pe],
                "llvm-readobj",
                &["--sections", "{path}"],
                true,
            ),
            command(
                "otool-l",
                "otool -l",
                "Mach-O load commands",
                &[MachO],
                "otool",
                &["-l", "{path}"],
                true,
            ),
            command(
                "elf-program-headers",
                "readelf -lW",
                "ELF program headers and segment mapping",
                &[Elf],
                "readelf",
                &["-lW", "{path}"],
                true,
            ),
            command(
                "elf-sections",
                "readelf -SW",
                "ELF section table",
                &[Elf],
                "readelf",
                &["-SW", "{path}"],
                true,
            ),
            command(
                "elf-notes",
                "readelf -nW",
                "ELF notes, build ID, and ABI properties",
                &[Elf],
                "readelf",
                &["-nW", "{path}"],
                true,
            ),
            command(
                "pe-detail",
                "objdump -p",
                "PE private headers, data directories, and imports",
                &[Pe],
                "objdump",
                &["-p", "{path}"],
                true,
            ),
            command(
                "size",
                "size",
                "Text, data, and BSS sizes",
                &[Elf, MachO, Pe],
                "size",
                &["{path}"],
                true,
            ),
            command(
                "nm-j",
                "nm -j",
                "Symbol names without address or type noise",
                &[Elf, MachO, Pe],
                "nm",
                &["-j", "{path}"],
                true,
            ),
            command(
                "nm",
                "nm",
                "Symbol table",
                &[Elf, MachO, Pe],
                "nm",
                &["{path}"],
                true,
            ),
            command(
                "elf-relocations",
                "readelf -rW",
                "ELF relocations",
                &[Elf],
                "readelf",
                &["-rW", "{path}"],
                true,
            ),
            command(
                "pe-relocations",
                "llvm-readobj (PE relocations)",
                "PE/COFF relocations",
                &[Pe],
                "llvm-readobj",
                &["--relocations", "{path}"],
                true,
            ),
            command(
                "macho-relocations",
                "otool -rv",
                "Mach-O relocations",
                &[MachO],
                "otool",
                &["-rv", "{path}"],
                true,
            ),
            command(
                "dsymutil-s",
                "dsymutil -s",
                "Mach-O debug map",
                &[MachO],
                "dsymutil",
                &["-s", "{path}"],
                true,
            ),
            command(
                "dwarfdump-uuid",
                "dwarfdump --uuid",
                "Mach-O UUIDs",
                &[MachO, FatMachO],
                "dwarfdump",
                &["--uuid", "{path}"],
                true,
            ),
            command(
                "codesign",
                "codesign -dvvv",
                "Mach-O code-signing identity, flags, hashes, and requirements",
                &[MachO, FatMachO],
                "codesign",
                &["-dvvv", "{path}"],
                true,
            ),
            command(
                "strings",
                "strings",
                "Printable strings",
                &[Elf, MachO, Pe],
                "strings",
                &["-a", "{path}"],
                true,
            ),
            command(
                "disassembly",
                "objdump -d",
                "Instruction-level disassembly (a deliberately late, noisy pass)",
                &[Elf, Pe],
                "objdump",
                &["-d", "{path}"],
                true,
            ),
            command(
                "macho-disassembly",
                "otool -tvV",
                "Mach-O instruction-level disassembly",
                &[MachO],
                "otool",
                &["-tvV", "{path}"],
                true,
            ),
            sparse_xxd(
                "xxd",
                "xxd",
                "Changed byte ranges with context; long equal regions are omitted",
            ),
        ];

        for pass in &mut passes {
            pass.lazy = matches!(
                pass.id.as_str(),
                "strings" | "disassembly" | "macho-disassembly" | "xxd"
            );
        }

        Self { passes }
    }

    pub fn applicable_indices(&self, comparison: &Comparison) -> Vec<usize> {
        self.passes
            .iter()
            .enumerate()
            .filter_map(|(index, pass)| pass.applies_to(comparison).then_some(index))
            .collect()
    }
}

fn internal(
    id: &str,
    title: &str,
    description: &str,
    formats: &[FormatKind],
    pass: InternalPass,
) -> PassSpec {
    PassSpec {
        id: id.into(),
        title: title.into(),
        description: description.into(),
        lazy: false,
        formats: formats.to_vec(),
        runner: Runner::Internal(pass),
    }
}

fn command(
    id: &str,
    title: &str,
    description: &str,
    formats: &[FormatKind],
    program: &str,
    args: &[&str],
    capture_stderr: bool,
) -> PassSpec {
    PassSpec {
        id: id.into(),
        title: title.into(),
        description: description.into(),
        lazy: false,
        formats: formats.to_vec(),
        runner: Runner::Command(CommandSpec {
            programs: preferred_programs(program),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            capture_stderr,
        }),
    }
}

fn preferred_programs(program: &str) -> Vec<String> {
    let llvm_program = match program {
        "ar" => Some("llvm-ar"),
        "dwarfdump" => Some("llvm-dwarfdump"),
        "lipo" => Some("llvm-lipo"),
        "nm" => Some("llvm-nm"),
        "objdump" => Some("llvm-objdump"),
        "otool" => Some("llvm-otool"),
        "readelf" => Some("llvm-readelf"),
        "size" => Some("llvm-size"),
        "strings" => Some("llvm-strings"),
        _ => None,
    };
    llvm_program.map_or_else(
        || vec![program.to_owned()],
        |llvm_program| vec![llvm_program.to_owned(), program.to_owned()],
    )
}

fn sparse_xxd(id: &str, title: &str, description: &str) -> PassSpec {
    PassSpec {
        id: id.into(),
        title: title.into(),
        description: description.into(),
        lazy: false,
        formats: Vec::new(),
        runner: Runner::SparseXxd,
    }
}

#[derive(Clone, Debug)]
pub struct PassOutput {
    pub left: String,
    pub right: String,
}

impl PassOutput {
    pub fn diff(&self) -> DiffView {
        DiffView::new(&self.left, &self.right)
    }
}

pub fn run_comparison(
    comparison: &Comparison,
    pass: &PassSpec,
    tool_timeout: Duration,
    cancellation: Option<&AtomicBool>,
) -> PassOutput {
    if matches!(pass.runner, Runner::SparseXxd) {
        return run_sparse_xxd(comparison, tool_timeout, cancellation);
    }
    PassOutput {
        left: run_side(comparison.left.as_ref(), pass, tool_timeout, cancellation),
        right: run_side(comparison.right.as_ref(), pass, tool_timeout, cancellation),
    }
}

fn run_side(
    artifact: Option<&Arc<Artifact>>,
    pass: &PassSpec,
    tool_timeout: Duration,
    cancellation: Option<&AtomicBool>,
) -> String {
    let Some(artifact) = artifact else {
        return "[missing on this side]".into();
    };
    if !pass.applies_to_kind(artifact.kind) {
        return format!("[not applicable to {}]", artifact.kind.name());
    }

    match &pass.runner {
        Runner::Internal(InternalPass::Overview) => overview(artifact),
        Runner::Command(command) => run_command(
            command,
            artifact,
            MAX_COMMAND_OUTPUT_BYTES,
            tool_timeout,
            cancellation,
        ),
        Runner::SparseXxd => unreachable!("paired xxd pass is handled before individual sides"),
    }
}

fn mask_macho_code_signature(mut bytes: Vec<u8>) -> Result<Vec<u8>> {
    let magic = bytes.get(..4).context("truncated Mach-O header")?;
    let (little_endian, is_64) = match magic {
        b"\xfe\xed\xfa\xce" => (false, false),
        b"\xce\xfa\xed\xfe" => (true, false),
        b"\xfe\xed\xfa\xcf" => (false, true),
        b"\xcf\xfa\xed\xfe" => (true, true),
        _ => bail!("not a thin Mach-O file"),
    };
    let read_u32 = |offset: usize| -> Result<u32> {
        let value: [u8; 4] = bytes
            .get(offset..offset + 4)
            .context("truncated Mach-O header")?
            .try_into()
            .unwrap();
        Ok(if little_endian {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        })
    };
    let command_count = read_u32(16)? as usize;
    if command_count > 65_536 {
        bail!("implausible Mach-O load command count: {command_count}");
    }
    let header_size = if is_64 { 32 } else { 28 };
    let mut command_offset = header_size;
    let mut signatures = Vec::new();
    for _ in 0..command_count {
        let command = read_u32(command_offset)?;
        let command_size = read_u32(command_offset + 4)? as usize;
        if command_size < 8 {
            bail!("invalid Mach-O load command size {command_size}");
        }
        let command_end = command_offset
            .checked_add(command_size)
            .context("Mach-O load command range overflow")?;
        if command_end > bytes.len() {
            bail!("Mach-O load command extends beyond the file");
        }
        if command == 0x1d {
            if command_size < 16 {
                bail!("truncated LC_CODE_SIGNATURE command");
            }
            let data_offset = read_u32(command_offset + 8)? as usize;
            let data_size = read_u32(command_offset + 12)? as usize;
            let data_end = data_offset
                .checked_add(data_size)
                .context("Mach-O code signature range overflow")?;
            if data_end > bytes.len() {
                bail!("Mach-O code signature extends beyond the file");
            }
            signatures.push((command_offset + 8, data_offset, data_end));
        }
        command_offset = command_end;
    }

    let mut truncate_at = None;
    for (fields, data_offset, data_end) in signatures {
        bytes[fields..fields + 8].fill(0);
        if data_end == bytes.len() {
            truncate_at = Some(data_offset);
        } else {
            bytes[data_offset..data_end].fill(0);
        }
    }
    if let Some(length) = truncate_at {
        bytes.truncate(length);
    }
    Ok(bytes)
}

fn overview(artifact: &Artifact) -> String {
    let mut lines = vec![
        format!("name: {}", artifact.label),
        format!("format: {}", artifact.kind.name()),
        format!("size: {} bytes", artifact.size),
    ];
    match fs::read(&artifact.path) {
        Ok(bytes) => {
            lines.push(format!("sha256: {}", sha256(&bytes)));
            if artifact.kind == FormatKind::MachO {
                match mask_macho_code_signature(bytes) {
                    Ok(masked) => lines.push(format!(
                        "sha256 (code signature masked): {}",
                        sha256(&masked)
                    )),
                    Err(error) => lines.push(format!(
                        "sha256 (code signature masked): [failed: {error:#}]"
                    )),
                }
            }
        }
        Err(error) => lines.push(format!("sha256: [failed to read artifact: {error}]")),
    }
    for (key, value) in &artifact.metadata {
        lines.push(format!("{key}: {value}"));
    }
    if !artifact.children.is_empty() {
        lines.push("contents:".into());
        for child in &artifact.children {
            lines.push(format!(
                "  {}  ({}; {} bytes)",
                child.label,
                child.kind.name(),
                child.size
            ));
        }
    }
    lines.join("\n")
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn run_sparse_xxd(
    comparison: &Comparison,
    tool_timeout: Duration,
    cancellation: Option<&AtomicBool>,
) -> PassOutput {
    match (&comparison.left, &comparison.right) {
        (Some(left), Some(right)) => {
            let (ranges, total_rows) = match changed_xxd_ranges(left, right, cancellation) {
                Ok(result) => result,
                Err(error) => {
                    let message = format!("[failed to locate changed bytes: {error}]");
                    return PassOutput {
                        left: message.clone(),
                        right: message,
                    };
                }
            };
            if ranges.is_empty() {
                return PassOutput {
                    left: "[no byte differences]".into(),
                    right: "[no byte differences]".into(),
                };
            }
            PassOutput {
                left: render_sparse_xxd(left, &ranges, total_rows, tool_timeout, cancellation),
                right: render_sparse_xxd(right, &ranges, total_rows, tool_timeout, cancellation),
            }
        }
        (left, right) => PassOutput {
            left: render_full_xxd(left.as_deref(), tool_timeout, cancellation),
            right: render_full_xxd(right.as_deref(), tool_timeout, cancellation),
        },
    }
}

fn changed_xxd_ranges(
    left: &Artifact,
    right: &Artifact,
    cancellation: Option<&AtomicBool>,
) -> io::Result<(Vec<(u64, u64)>, u64)> {
    let mut left = BufReader::new(fs::File::open(&left.path)?);
    let mut right = BufReader::new(fs::File::open(&right.path)?);
    let mut left_row = [0_u8; XXD_ROW_BYTES as usize];
    let mut right_row = [0_u8; XXD_ROW_BYTES as usize];
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut row = 0_u64;

    loop {
        if row.is_multiple_of(4096) && cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "comparison cancelled",
            ));
        }
        let left_count = read_row(&mut left, &mut left_row)?;
        let right_count = read_row(&mut right, &mut right_row)?;
        if left_count == 0 && right_count == 0 {
            break;
        }
        if left_count != right_count || left_row[..left_count] != right_row[..right_count] {
            let start = row.saturating_sub(XXD_CONTEXT_ROWS);
            let end = row.saturating_add(XXD_CONTEXT_ROWS + 1);
            match ranges.last_mut() {
                Some((_, previous_end)) if start <= *previous_end => {
                    *previous_end = (*previous_end).max(end);
                }
                _ => ranges.push((start, end)),
            }
        }
        row += 1;
    }
    for (_, end) in &mut ranges {
        *end = (*end).min(row);
    }
    Ok((ranges, row))
}

fn read_row(reader: &mut impl Read, row: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < row.len() {
        let count = reader.read(&mut row[filled..])?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    Ok(filled)
}

fn render_sparse_xxd(
    artifact: &Artifact,
    ranges: &[(u64, u64)],
    total_rows: u64,
    tool_timeout: Duration,
    cancellation: Option<&AtomicBool>,
) -> String {
    let mut output = String::new();
    let mut previous_end = 0;
    for (start, end) in ranges {
        if *start > previous_end {
            let bytes = (start - previous_end) * XXD_ROW_BYTES;
            append_sparse_output(
                &mut output,
                &format!("-------- {bytes} unchanged bytes omitted --------\n"),
            );
        }
        let offset = start * XXD_ROW_BYTES;
        let length = (end - start) * XXD_ROW_BYTES;
        let command = CommandSpec {
            programs: vec!["xxd".into()],
            args: vec![
                "-g".into(),
                "1".into(),
                "-c".into(),
                "16".into(),
                "-s".into(),
                offset.to_string(),
                "-l".into(),
                length.to_string(),
                "{path}".into(),
            ],
            capture_stderr: true,
        };
        let rendered = run_command(
            &command,
            artifact,
            MAX_COMMAND_OUTPUT_BYTES,
            tool_timeout,
            cancellation,
        );
        if !append_sparse_output(&mut output, &rendered) {
            break;
        }
        previous_end = *end;
    }
    if output.len() < MAX_SPARSE_XXD_OUTPUT_BYTES && previous_end < total_rows {
        let bytes = (total_rows - previous_end) * XXD_ROW_BYTES;
        append_sparse_output(
            &mut output,
            &format!("-------- up to {bytes} unchanged bytes omitted --------\n"),
        );
    }
    output
}

fn append_sparse_output(output: &mut String, text: &str) -> bool {
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    let remaining = MAX_SPARSE_XXD_OUTPUT_BYTES.saturating_sub(output.len());
    if text.len() <= remaining {
        output.push_str(text);
        return true;
    }
    let mut end = remaining.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    output.push_str(&text[..end]);
    output.push_str(&format!(
        "\n[output truncated after {MAX_SPARSE_XXD_OUTPUT_BYTES} bytes]"
    ));
    false
}

fn render_full_xxd(
    artifact: Option<&Artifact>,
    tool_timeout: Duration,
    cancellation: Option<&AtomicBool>,
) -> String {
    let Some(artifact) = artifact else {
        return "[missing on this side]".into();
    };
    let command = CommandSpec {
        programs: vec!["xxd".into()],
        args: vec![
            "-g".into(),
            "1".into(),
            "-c".into(),
            "16".into(),
            "{path}".into(),
        ],
        capture_stderr: true,
    };
    run_command(
        &command,
        artifact,
        MAX_COMMAND_OUTPUT_BYTES,
        tool_timeout,
        cancellation,
    )
}

fn run_command(
    command: &CommandSpec,
    artifact: &Artifact,
    max_bytes: usize,
    tool_timeout: Duration,
    cancellation: Option<&AtomicBool>,
) -> String {
    let path = artifact.path.to_string_lossy();
    let args = command
        .args
        .iter()
        .map(|arg| arg.replace("{path}", &path))
        .collect::<Vec<_>>();
    let mut spawned = None;
    for program in &command.programs {
        match Command::new(program)
            .args(&args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("TZ", "UTC")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => {
                spawned = Some((program.clone(), child));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return format!("[failed to run {program}: {error}]"),
        }
    }
    let Some((program, mut child)) = spawned else {
        return format!("[tool unavailable: tried {}]", command.programs.join(", "));
    };

    let limit_hit = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().expect("configured piped stdout");
    let stderr = child.stderr.take().expect("configured piped stderr");
    let stdout_limit = limit_hit.clone();
    let stdout_reader = thread::spawn(move || read_bounded(stdout, max_bytes, Some(stdout_limit)));
    let stderr_limit = command.capture_stderr.then(|| limit_hit.clone());
    let stderr_bytes = if command.capture_stderr { max_bytes } else { 0 };
    let stderr_reader = thread::spawn(move || read_bounded(stderr, stderr_bytes, stderr_limit));

    let mut terminated_for_limit = false;
    let mut timed_out = false;
    let mut cancelled = false;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed)) => {
                cancelled = true;
                let _ = child.kill();
                break child.wait();
            }
            Ok(None) if limit_hit.load(Ordering::Relaxed) => {
                terminated_for_limit = true;
                let _ = child.kill();
                break child.wait();
            }
            Ok(None) if !tool_timeout.is_zero() && started.elapsed() >= tool_timeout => {
                timed_out = true;
                let _ = child.kill();
                break child.wait();
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(error) => break Err(error),
        }
    };
    let status = match status {
        Ok(status) => status,
        Err(error) => return format!("[failed while waiting for {program}: {error}]"),
    };
    let mut bytes = stdout_reader
        .join()
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let stderr = stderr_reader
        .join()
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    if command.capture_stderr && !stderr.is_empty() {
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(&stderr);
    }
    let mut text = limited_lossy(&bytes, max_bytes);
    text = text.replace(path.as_ref(), "<file>");
    let output_was_limited = limit_hit.load(Ordering::Relaxed);
    if cancelled {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("[tool cancelled]");
    } else if timed_out {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!(
            "[tool timed out after {} seconds]",
            tool_timeout.as_secs()
        ));
    } else if output_was_limited {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        if terminated_for_limit {
            text.push_str(&format!(
                "[output limit reached; process stopped after {max_bytes} bytes]"
            ));
        } else {
            text.push_str(&format!("[output truncated after {max_bytes} bytes]"));
        }
    } else if !status.success() {
        let status = status
            .code()
            .map_or_else(|| "signal".into(), |code| code.to_string());
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("[exit status: {status}]"));
    }
    if text.is_empty() {
        "[no output]".into()
    } else {
        text
    }
}

fn read_bounded(
    mut reader: impl Read,
    limit: usize,
    limit_hit: Option<Arc<AtomicBool>>,
) -> io::Result<Vec<u8>> {
    let mut captured = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(captured.len());
        captured.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining
            && let Some(limit_hit) = &limit_hit
        {
            limit_hit.store(true, Ordering::Relaxed);
        }
    }
    Ok(captured)
}

fn limited_lossy(bytes: &[u8], limit: usize) -> String {
    if bytes.len() <= limit {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut output = String::from_utf8_lossy(&bytes[..limit]).into_owned();
    output.push_str(&format!(
        "\n[output truncated: captured {} of {} bytes]",
        limit,
        bytes.len()
    ));
    output
}

pub fn run_report(
    analysis: &Analysis,
    registry: &PassRegistry,
    timeout_seconds: u64,
) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for comparison in &analysis.comparisons {
        for pass_index in registry.applicable_indices(comparison) {
            let pass = &registry.passes[pass_index];
            let result =
                run_comparison(comparison, pass, Duration::from_secs(timeout_seconds), None);
            let diff = result.diff();
            writeln!(
                output,
                "== {}{} :: {} ({}) ==",
                "  ".repeat(comparison.depth),
                comparison.label,
                pass.title,
                if diff.incomplete && diff.identical {
                    "incomplete; captured output identical"
                } else if diff.incomplete {
                    "incomplete; captured output different"
                } else if diff.identical {
                    "identical"
                } else {
                    "different"
                }
            )?;
            if !diff.identical {
                write!(output, "{}", diff.unified())?;
            } else if diff.incomplete {
                for line in result.left.lines().filter(|line| {
                    line.starts_with("[tool unavailable:")
                        || line.starts_with("[failed")
                        || line.starts_with("[tool timed out")
                        || line.starts_with("[tool cancelled")
                        || line.starts_with("[output limit reached;")
                        || line.starts_with("[output truncated")
                }) {
                    writeln!(output, "  {line}")?;
                }
            }
            writeln!(output)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn xxd_is_the_last_builtin_pass() {
        let registry = PassRegistry::builtin();
        assert_eq!(registry.passes.last().unwrap().id, "xxd");
        assert!(matches!(
            registry.passes.last().unwrap().runner,
            Runner::SparseXxd
        ));
    }

    #[test]
    fn only_high_volume_builtin_passes_are_lazy() {
        let registry = PassRegistry::builtin();
        let lazy = registry
            .passes
            .iter()
            .filter(|pass| pass.is_lazy())
            .map(|pass| pass.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            lazy,
            vec!["strings", "disassembly", "macho-disassembly", "xxd"]
        );
    }

    #[test]
    fn name_only_nm_runs_for_every_supported_object_format() {
        let registry = PassRegistry::builtin();
        let pass = registry
            .passes
            .iter()
            .find(|pass| pass.id == "nm-j")
            .unwrap();
        assert!(pass.applies_to_kind(FormatKind::Elf));
        assert!(pass.applies_to_kind(FormatKind::MachO));
        assert!(pass.applies_to_kind(FormatKind::Pe));
        assert!(!pass.applies_to_kind(FormatKind::Archive));
    }

    #[test]
    fn llvm_tools_are_preferred_with_system_fallbacks() {
        assert_eq!(preferred_programs("otool"), ["llvm-otool", "otool"]);
        assert_eq!(preferred_programs("readelf"), ["llvm-readelf", "readelf"]);
        assert_eq!(preferred_programs("size"), ["llvm-size", "size"]);
        assert_eq!(preferred_programs("nm"), ["llvm-nm", "nm"]);
        assert_eq!(preferred_programs("xxd"), ["xxd"]);
        assert_eq!(preferred_programs("codesign"), ["codesign"]);
    }

    #[test]
    fn masks_a_trailing_macho_code_signature() {
        let mut first = vec![0_u8; 64];
        first[0..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        first[16..20].copy_from_slice(&1_u32.to_le_bytes());
        first[20..24].copy_from_slice(&16_u32.to_le_bytes());
        first[32..36].copy_from_slice(&0x1d_u32.to_le_bytes());
        first[36..40].copy_from_slice(&16_u32.to_le_bytes());
        first[40..44].copy_from_slice(&48_u32.to_le_bytes());
        first[44..48].copy_from_slice(&16_u32.to_le_bytes());
        first[48..].fill(0xaa);
        let mut second = first.clone();
        second[48..].fill(0xbb);
        assert_ne!(first, second);
        assert_eq!(
            mask_macho_code_signature(first).unwrap(),
            mask_macho_code_signature(second).unwrap()
        );
    }

    #[test]
    fn bounded_reader_discards_excess_and_signals_the_limit() {
        let limit_hit = Arc::new(AtomicBool::new(false));
        let captured =
            read_bounded(Cursor::new(vec![0xab; 100]), 8, Some(limit_hit.clone())).unwrap();
        assert_eq!(captured, vec![0xab; 8]);
        assert!(limit_hit.load(Ordering::Relaxed));
    }

    #[test]
    fn sparse_xxd_ranges_merge_context_without_capturing_equal_regions() {
        let directory = tempfile::tempdir().unwrap();
        let left_path = directory.path().join("left.bin");
        let right_path = directory.path().join("right.bin");
        let left_bytes = vec![0_u8; 30 * XXD_ROW_BYTES as usize];
        let mut right_bytes = left_bytes.clone();
        right_bytes[10 * XXD_ROW_BYTES as usize + 2] = 1;
        right_bytes[15 * XXD_ROW_BYTES as usize] = 2;
        fs::write(&left_path, &left_bytes).unwrap();
        fs::write(&right_path, &right_bytes).unwrap();
        let artifact = |path, label: &str| Artifact {
            label: label.into(),
            match_key: label.into(),
            path,
            kind: FormatKind::Unknown,
            size: left_bytes.len() as u64,
            metadata: Vec::new(),
            children: Vec::new(),
        };
        let left = artifact(left_path, "left");
        let right = artifact(right_path, "right");
        let (ranges, total_rows) = changed_xxd_ranges(&left, &right, None).unwrap();
        assert_eq!(ranges, vec![(7, 19)]);
        assert_eq!(total_rows, 30);
    }

    #[cfg(unix)]
    #[test]
    fn command_timeout_stops_a_tool() {
        let artifact = Artifact {
            label: "fixture".into(),
            match_key: "fixture".into(),
            path: std::path::Path::new("/dev/null").into(),
            kind: FormatKind::Unknown,
            size: 0,
            metadata: Vec::new(),
            children: Vec::new(),
        };
        let command = CommandSpec {
            programs: vec!["sleep".into()],
            args: vec!["10".into()],
            capture_stderr: true,
        };
        let output = run_command(&command, &artifact, 1024, Duration::from_millis(20), None);
        assert!(output.contains("[tool timed out"));
    }
}
