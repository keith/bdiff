use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tempfile::TempDir;

const AR_MAGIC: &[u8] = b"!<arch>\n";
const THIN_AR_MAGIC: &[u8] = b"!<thin>\n";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FormatKind {
    Elf,
    MachO,
    Pe,
    Archive,
    FatMachO,
    Unknown,
}

impl FormatKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Pe => "PE/COFF",
            Self::Archive => "archive",
            Self::FatMachO => "fat Mach-O",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Artifact {
    pub label: String,
    pub match_key: String,
    pub path: PathBuf,
    pub kind: FormatKind,
    pub size: u64,
    pub metadata: Vec<(String, String)>,
    pub children: Vec<Arc<Artifact>>,
}

#[derive(Clone, Debug)]
pub struct Comparison {
    pub id: usize,
    pub label: String,
    pub depth: usize,
    pub left: Option<Arc<Artifact>>,
    pub right: Option<Arc<Artifact>>,
}

impl Comparison {
    pub fn side_marker(&self) -> &'static str {
        match (&self.left, &self.right) {
            (Some(_), Some(_)) => " ",
            (Some(_), None) => "-",
            (None, Some(_)) => "+",
            (None, None) => "?",
        }
    }
}

pub struct Analysis {
    // Extracted members must remain alive as long as passes can execute.
    _tempdir: TempDir,
    pub comparisons: Vec<Comparison>,
}

impl Analysis {
    pub fn open(left: &Path, right: &Path, max_depth: usize) -> Result<Self> {
        let tempdir = tempfile::Builder::new()
            .prefix("bindiff-")
            .tempdir()
            .context("failed to create extraction directory")?;
        let mut loader = Loader {
            tempdir: tempdir.path().to_path_buf(),
            next_file: 0,
            max_depth,
        };

        let left_artifact = loader.load_path(left, display_name(left), 0)?;
        let right_artifact = loader.load_path(right, display_name(right), 0)?;
        let mut comparisons = Vec::new();
        pair_artifacts(
            Some(left_artifact),
            Some(right_artifact),
            0,
            &mut comparisons,
        );

        Ok(Self {
            _tempdir: tempdir,
            comparisons,
        })
    }
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

struct Loader {
    tempdir: PathBuf,
    next_file: usize,
    max_depth: usize,
}

impl Loader {
    fn load_path(&mut self, path: &Path, label: String, depth: usize) -> Result<Arc<Artifact>> {
        let data =
            fs::read(path).with_context(|| format!("failed to read input {}", path.display()))?;
        let mut metadata = filesystem_metadata(path);
        metadata.push(("input path".into(), path.display().to_string()));
        self.load_bytes(
            path.to_path_buf(),
            label.clone(),
            label,
            data,
            depth,
            metadata,
        )
    }

    fn load_bytes(
        &mut self,
        path: PathBuf,
        label: String,
        match_key: String,
        data: Vec<u8>,
        depth: usize,
        mut metadata: Vec<(String, String)>,
    ) -> Result<Arc<Artifact>> {
        let kind = detect_format(&data);
        let size = data.len() as u64;
        let children = if depth >= self.max_depth {
            metadata.push((
                "discovery".into(),
                format!("stopped at configured depth {}", self.max_depth),
            ));
            Vec::new()
        } else {
            match kind {
                FormatKind::Archive => {
                    self.load_archive_members(&path, &data, depth + 1, &mut metadata)?
                }
                FormatKind::FatMachO => self.load_fat_slices(&data, depth + 1, &mut metadata)?,
                _ => Vec::new(),
            }
        };

        Ok(Arc::new(Artifact {
            label,
            match_key,
            path,
            kind,
            size,
            metadata,
            children,
        }))
    }

    fn materialize(&mut self, bytes: &[u8], extension: &str) -> Result<PathBuf> {
        let path = self
            .tempdir
            .join(format!("member-{:08}.{extension}", self.next_file));
        self.next_file += 1;
        fs::write(&path, bytes)
            .with_context(|| format!("failed to extract member to {}", path.display()))?;
        Ok(path)
    }

    fn load_archive_members(
        &mut self,
        archive_path: &Path,
        data: &[u8],
        depth: usize,
        metadata: &mut Vec<(String, String)>,
    ) -> Result<Vec<Arc<Artifact>>> {
        if data.starts_with(THIN_AR_MAGIC) {
            metadata.push(("archive kind".into(), "thin archive".into()));
            let members = parse_thin_archive(data)?;
            let mut children = Vec::new();
            let mut occurrences: HashMap<String, usize> = HashMap::new();
            for member in members {
                let occurrence = occurrences.entry(member.name.clone()).or_default();
                let match_key = format!("{}#{}", member.name, *occurrence);
                *occurrence += 1;
                let label = if *occurrence > 1 {
                    format!("{} ({})", member.name, *occurrence)
                } else {
                    member.name.clone()
                };
                let member_path = if Path::new(&member.name).is_absolute() {
                    PathBuf::from(&member.name)
                } else {
                    archive_path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(&member.name)
                };
                match fs::read(&member_path) {
                    Ok(member_data) => {
                        let member_metadata = vec![
                            ("thin archive member".into(), member.name),
                            ("referenced path".into(), member_path.display().to_string()),
                            ("mtime".into(), member.mtime),
                            ("uid".into(), member.uid),
                            ("gid".into(), member.gid),
                            ("mode".into(), member.mode),
                        ];
                        children.push(self.load_bytes(
                            member_path,
                            label,
                            match_key,
                            member_data,
                            depth,
                            member_metadata,
                        )?);
                    }
                    Err(error) => {
                        metadata.push((format!("unavailable member {label}"), error.to_string()))
                    }
                }
            }
            metadata.push(("available members".into(), children.len().to_string()));
            return Ok(children);
        }

        let members = parse_archive(data)?;
        let mut children = Vec::new();
        let mut occurrences: HashMap<String, usize> = HashMap::new();
        for member in members {
            if member.special {
                continue;
            }
            let occurrence = occurrences.entry(member.name.clone()).or_default();
            let match_key = format!("{}#{}", member.name, *occurrence);
            *occurrence += 1;
            let label = if *occurrence > 1 {
                format!("{} ({})", member.name, *occurrence)
            } else {
                member.name.clone()
            };
            let path = self.materialize(member.data, "o")?;
            let member_metadata = vec![
                ("archive member".into(), member.name),
                ("mtime".into(), member.mtime),
                ("uid".into(), member.uid),
                ("gid".into(), member.gid),
                ("mode".into(), member.mode),
            ];
            children.push(self.load_bytes(
                path,
                label,
                match_key,
                member.data.to_vec(),
                depth,
                member_metadata,
            )?);
        }
        metadata.push(("members".into(), children.len().to_string()));
        Ok(children)
    }

    fn load_fat_slices(
        &mut self,
        data: &[u8],
        depth: usize,
        metadata: &mut Vec<(String, String)>,
    ) -> Result<Vec<Arc<Artifact>>> {
        let slices = parse_fat_macho(data)?;
        let mut children = Vec::with_capacity(slices.len());
        let mut occurrences: HashMap<String, usize> = HashMap::new();
        for slice in slices {
            let base_label = cpu_name(slice.cpu_type).to_owned();
            let occurrence = occurrences.entry(base_label.clone()).or_default();
            let match_key = format!("{:08x}#{}", slice.cpu_type, *occurrence);
            *occurrence += 1;
            let label = if *occurrence > 1 {
                format!("{} ({})", base_label, *occurrence)
            } else {
                base_label
            };
            let path = self.materialize(slice.data, "macho")?;
            let slice_metadata = vec![
                ("CPU type".into(), format!("0x{:08x}", slice.cpu_type)),
                ("CPU subtype".into(), format!("0x{:08x}", slice.cpu_subtype)),
                ("alignment".into(), format!("2^{}", slice.alignment)),
                ("container offset".into(), slice.offset.to_string()),
            ];
            children.push(self.load_bytes(
                path,
                label,
                match_key,
                slice.data.to_vec(),
                depth,
                slice_metadata,
            )?);
        }
        metadata.push(("architectures".into(), children.len().to_string()));
        Ok(children)
    }
}

fn filesystem_metadata(path: &Path) -> Vec<(String, String)> {
    let Ok(metadata) = fs::metadata(path) else {
        return Vec::new();
    };
    let mut result = vec![(
        "read-only".into(),
        metadata.permissions().readonly().to_string(),
    )];
    if let Ok(modified) = metadata.modified()
        && let Ok(since_epoch) = modified.duration_since(std::time::UNIX_EPOCH)
    {
        result.push((
            "modified".into(),
            format!(
                "{}.{:09} UTC",
                since_epoch.as_secs(),
                since_epoch.subsec_nanos()
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        result.push((
            "mode".into(),
            format!("{:04o}", metadata.permissions().mode() & 0o7777),
        ));
        result.push(("uid".into(), metadata.uid().to_string()));
        result.push(("gid".into(), metadata.gid().to_string()));
    }
    result
}

fn pair_artifacts(
    left: Option<Arc<Artifact>>,
    right: Option<Arc<Artifact>>,
    depth: usize,
    output: &mut Vec<Comparison>,
) {
    let label = match (&left, &right) {
        (Some(left), Some(right)) if left.label != right.label && depth == 0 => {
            format!("{} ↔ {}", left.label, right.label)
        }
        (Some(left), _) => left.label.clone(),
        (_, Some(right)) => right.label.clone(),
        _ => return,
    };
    let id = output.len();
    output.push(Comparison {
        id,
        label,
        depth,
        left: left.clone(),
        right: right.clone(),
    });

    let left_children = left.as_ref().map_or(&[][..], |item| &item.children);
    let right_children = right.as_ref().map_or(&[][..], |item| &item.children);
    let mut right_by_key: HashMap<&str, VecDeque<Arc<Artifact>>> = HashMap::new();
    for child in right_children {
        right_by_key
            .entry(&child.match_key)
            .or_default()
            .push_back(child.clone());
    }

    for child in left_children {
        let paired = right_by_key
            .get_mut(child.match_key.as_str())
            .and_then(VecDeque::pop_front);
        pair_artifacts(Some(child.clone()), paired, depth + 1, output);
    }
    for child in right_children {
        let queue = right_by_key.get_mut(child.match_key.as_str()).unwrap();
        if let Some(unmatched) = queue.pop_front() {
            pair_artifacts(None, Some(unmatched), depth + 1, output);
        }
    }
}

pub fn detect_format(data: &[u8]) -> FormatKind {
    if data.starts_with(AR_MAGIC) || data.starts_with(THIN_AR_MAGIC) {
        return FormatKind::Archive;
    }
    if data.starts_with(b"\x7fELF") {
        return FormatKind::Elf;
    }
    if is_fat_macho(data) {
        return FormatKind::FatMachO;
    }
    if is_thin_macho(data) {
        return FormatKind::MachO;
    }
    if is_pe(data) {
        return FormatKind::Pe;
    }
    if is_coff(data) {
        return FormatKind::Pe;
    }
    FormatKind::Unknown
}

fn is_thin_macho(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some(b"\xfe\xed\xfa\xce")
            | Some(b"\xce\xfa\xed\xfe")
            | Some(b"\xfe\xed\xfa\xcf")
            | Some(b"\xcf\xfa\xed\xfe")
    )
}

fn is_fat_macho(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some(b"\xca\xfe\xba\xbe")
            | Some(b"\xbe\xba\xfe\xca")
            | Some(b"\xca\xfe\xba\xbf")
            | Some(b"\xbf\xba\xfe\xca")
    )
}

fn is_pe(data: &[u8]) -> bool {
    if !data.starts_with(b"MZ") || data.len() < 0x40 {
        return false;
    }
    let offset = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    data.get(offset..offset.saturating_add(4)) == Some(b"PE\0\0")
}

fn is_coff(data: &[u8]) -> bool {
    let known_machine = |machine: u16| {
        matches!(
            machine,
            0x014c // IMAGE_FILE_MACHINE_I386
                | 0x8664 // IMAGE_FILE_MACHINE_AMD64
                | 0x01c0 // IMAGE_FILE_MACHINE_ARM
                | 0x01c2 // IMAGE_FILE_MACHINE_THUMB
                | 0x01c4 // IMAGE_FILE_MACHINE_ARMNT
                | 0xaa64 // IMAGE_FILE_MACHINE_ARM64
        )
    };
    if data.len() < 20 {
        return false;
    }
    // Anonymous/import and bigobj COFF headers begin with this signature and
    // carry the machine field at byte 6.
    if data.starts_with(b"\0\0\xff\xff") {
        let machine = u16::from_le_bytes([data[6], data[7]]);
        return known_machine(machine);
    }
    let machine = u16::from_le_bytes([data[0], data[1]]);
    let sections = u16::from_le_bytes([data[2], data[3]]) as usize;
    let optional_header_size = u16::from_le_bytes([data[16], data[17]]) as usize;
    let section_table_end = 20_usize
        .saturating_add(optional_header_size)
        .saturating_add(sections.saturating_mul(40));
    known_machine(machine) && sections > 0 && sections < 32_768 && section_table_end <= data.len()
}

struct ArchiveMember<'a> {
    name: String,
    mtime: String,
    uid: String,
    gid: String,
    mode: String,
    data: &'a [u8],
    special: bool,
}

fn parse_archive(data: &[u8]) -> Result<Vec<ArchiveMember<'_>>> {
    if !data.starts_with(AR_MAGIC) {
        bail!("invalid regular archive magic");
    }
    let mut offset = AR_MAGIC.len();
    let mut string_table: Option<&[u8]> = None;
    let mut result = Vec::new();
    while offset < data.len() {
        if !offset.is_multiple_of(2) {
            offset += 1;
        }
        if offset == data.len() {
            break;
        }
        let header = data
            .get(offset..offset + 60)
            .context("truncated archive member header")?;
        if &header[58..60] != b"`\n" {
            bail!("invalid archive member trailer at offset {offset}");
        }
        let raw_name = ascii_field(&header[0..16]);
        let mtime = ascii_field(&header[16..28]);
        let uid = ascii_field(&header[28..34]);
        let gid = ascii_field(&header[34..40]);
        let mode = ascii_field(&header[40..48]);
        let stored_size: usize = ascii_field(&header[48..58])
            .parse()
            .with_context(|| format!("invalid archive member size at offset {offset}"))?;
        let payload_start = offset + 60;
        let payload = data
            .get(payload_start..payload_start.saturating_add(stored_size))
            .context("truncated archive member data")?;

        let (name, member_data, special) = if raw_name == "//" {
            string_table = Some(payload);
            (raw_name, payload, true)
        } else if raw_name == "/" || raw_name.starts_with("/SYM64/") {
            (raw_name, payload, true)
        } else if let Some(length) = raw_name.strip_prefix("#1/") {
            let length: usize = length
                .parse()
                .with_context(|| format!("invalid BSD archive name length {length}"))?;
            let name_bytes = payload
                .get(..length)
                .context("BSD archive name extends beyond member")?;
            (
                String::from_utf8_lossy(name_bytes)
                    .trim_end_matches('\0')
                    .to_owned(),
                &payload[length..],
                false,
            )
        } else if let Some(table_offset) = raw_name.strip_prefix('/') {
            let table_offset: usize = table_offset
                .trim_end_matches('/')
                .parse()
                .with_context(|| format!("invalid GNU archive name offset {table_offset}"))?;
            let table = string_table.context("archive references a missing GNU string table")?;
            let tail = table
                .get(table_offset..)
                .context("GNU archive name offset is out of bounds")?;
            let end = tail
                .windows(2)
                .position(|window| window == b"/\n")
                .unwrap_or(tail.len());
            (
                String::from_utf8_lossy(&tail[..end]).into_owned(),
                payload,
                false,
            )
        } else {
            (raw_name.trim_end_matches('/').to_owned(), payload, false)
        };

        let special = special || name.starts_with("__.SYMDEF");
        result.push(ArchiveMember {
            name,
            mtime,
            uid,
            gid,
            mode,
            data: member_data,
            special,
        });
        offset = payload_start + stored_size;
    }
    Ok(result)
}

struct ThinArchiveMember {
    name: String,
    mtime: String,
    uid: String,
    gid: String,
    mode: String,
}

fn parse_thin_archive(data: &[u8]) -> Result<Vec<ThinArchiveMember>> {
    if !data.starts_with(THIN_AR_MAGIC) {
        bail!("invalid thin archive magic");
    }
    let mut offset = THIN_AR_MAGIC.len();
    let mut string_table: Option<&[u8]> = None;
    let mut result = Vec::new();
    while offset < data.len() {
        if !offset.is_multiple_of(2) {
            offset += 1;
        }
        if offset == data.len() {
            break;
        }
        let header = data
            .get(offset..offset + 60)
            .context("truncated thin archive member header")?;
        if &header[58..60] != b"`\n" {
            bail!("invalid thin archive member trailer at offset {offset}");
        }
        let raw_name = ascii_field(&header[0..16]);
        let mtime = ascii_field(&header[16..28]);
        let uid = ascii_field(&header[28..34]);
        let gid = ascii_field(&header[34..40]);
        let mode = ascii_field(&header[40..48]);
        let stored_size: usize = ascii_field(&header[48..58])
            .parse()
            .with_context(|| format!("invalid thin archive member size at offset {offset}"))?;
        let payload_start = offset + 60;

        if raw_name == "//" || raw_name == "/" || raw_name.starts_with("/SYM64/") {
            let payload = data
                .get(payload_start..payload_start.saturating_add(stored_size))
                .context("truncated thin archive index")?;
            if raw_name == "//" {
                string_table = Some(payload);
            }
            offset = payload_start + stored_size;
            continue;
        }

        let name = if let Some(table_offset) = raw_name.strip_prefix('/') {
            let table_offset: usize = table_offset
                .trim_end_matches('/')
                .parse()
                .with_context(|| format!("invalid thin archive name offset {table_offset}"))?;
            let table = string_table.context("thin archive references a missing string table")?;
            let tail = table
                .get(table_offset..)
                .context("thin archive name offset is out of bounds")?;
            let end = tail
                .windows(2)
                .position(|window| window == b"/\n")
                .unwrap_or(tail.len());
            String::from_utf8_lossy(&tail[..end]).into_owned()
        } else if let Some(length) = raw_name.strip_prefix("#1/") {
            let length: usize = length.parse().context("invalid BSD thin archive name")?;
            let name = data
                .get(payload_start..payload_start + length)
                .context("truncated BSD thin archive name")?;
            offset = payload_start + length;
            String::from_utf8_lossy(name)
                .trim_end_matches('\0')
                .to_owned()
        } else {
            raw_name.trim_end_matches('/').to_owned()
        };
        result.push(ThinArchiveMember {
            name,
            mtime,
            uid,
            gid,
            mode,
        });
        if !raw_name.starts_with("#1/") {
            // A thin member's declared size describes the external file; its bytes
            // are deliberately absent from the archive.
            offset = payload_start;
        }
    }
    Ok(result)
}

fn ascii_field(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

struct FatSlice<'a> {
    cpu_type: u32,
    cpu_subtype: u32,
    alignment: u32,
    offset: u64,
    data: &'a [u8],
}

fn parse_fat_macho(data: &[u8]) -> Result<Vec<FatSlice<'_>>> {
    let magic = data.get(..4).context("truncated fat Mach-O header")?;
    let (little_endian, is_64) = match magic {
        b"\xca\xfe\xba\xbe" => (false, false),
        b"\xbe\xba\xfe\xca" => (true, false),
        b"\xca\xfe\xba\xbf" => (false, true),
        b"\xbf\xba\xfe\xca" => (true, true),
        _ => bail!("invalid fat Mach-O magic"),
    };
    let count = read_u32(data, 4, little_endian)? as usize;
    if count > 256 {
        bail!("implausible fat Mach-O architecture count: {count}");
    }
    let entry_size = if is_64 { 32 } else { 20 };
    let mut slices = Vec::with_capacity(count);
    for index in 0..count {
        let base = 8 + index * entry_size;
        let cpu_type = read_u32(data, base, little_endian)?;
        let cpu_subtype = read_u32(data, base + 4, little_endian)?;
        let (offset, size, alignment) = if is_64 {
            (
                read_u64(data, base + 8, little_endian)?,
                read_u64(data, base + 16, little_endian)?,
                read_u32(data, base + 24, little_endian)?,
            )
        } else {
            (
                read_u32(data, base + 8, little_endian)? as u64,
                read_u32(data, base + 12, little_endian)? as u64,
                read_u32(data, base + 16, little_endian)?,
            )
        };
        let end = offset
            .checked_add(size)
            .context("fat Mach-O slice range overflow")?;
        let offset_usize = usize::try_from(offset).context("fat Mach-O offset is too large")?;
        let end_usize = usize::try_from(end).context("fat Mach-O end offset is too large")?;
        let slice = data
            .get(offset_usize..end_usize)
            .with_context(|| format!("fat Mach-O slice {index} is out of bounds"))?;
        slices.push(FatSlice {
            cpu_type,
            cpu_subtype,
            alignment,
            offset,
            data: slice,
        });
    }
    Ok(slices)
}

fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .context("truncated integer")?
        .try_into()
        .unwrap();
    Ok(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> Result<u64> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .context("truncated integer")?
        .try_into()
        .unwrap();
    Ok(if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn cpu_name(cpu_type: u32) -> &'static str {
    match cpu_type {
        7 => "i386",
        0x0100_0007 => "x86_64",
        12 => "arm",
        0x0100_000c => "arm64",
        18 => "ppc",
        0x0100_0012 => "ppc64",
        _ => "unknown-architecture",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_supported_formats() {
        assert_eq!(detect_format(b"\x7fELFrest"), FormatKind::Elf);
        assert_eq!(detect_format(b"!<arch>\n"), FormatKind::Archive);
        assert_eq!(detect_format(b"\xcf\xfa\xed\xfepayload"), FormatKind::MachO);
        assert_eq!(
            detect_format(b"\xca\xfe\xba\xbepayload"),
            FormatKind::FatMachO
        );
        assert_eq!(detect_format(b"plain text"), FormatKind::Unknown);

        let mut coff = vec![0_u8; 60];
        coff[0..2].copy_from_slice(&0x8664_u16.to_le_bytes());
        coff[2..4].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(detect_format(&coff), FormatKind::Pe);
    }

    #[test]
    fn parses_a_minimal_archive() {
        let mut archive = AR_MAGIC.to_vec();
        archive
            .extend_from_slice(b"foo.o/          0           0     0     644     3         `\nabc");
        archive.push(b'\n');
        let members = parse_archive(&archive).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "foo.o");
        assert_eq!(members[0].data, b"abc");
    }

    #[test]
    fn parses_a_fat_macho_slice() {
        let mut fat = Vec::new();
        fat.extend_from_slice(b"\xca\xfe\xba\xbe");
        fat.extend_from_slice(&1_u32.to_be_bytes());
        fat.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
        fat.extend_from_slice(&0_u32.to_be_bytes());
        fat.extend_from_slice(&28_u32.to_be_bytes());
        fat.extend_from_slice(&4_u32.to_be_bytes());
        fat.extend_from_slice(&2_u32.to_be_bytes());
        fat.extend_from_slice(b"\xcf\xfa\xed\xfe");
        let slices = parse_fat_macho(&fat).unwrap();
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].cpu_type, 0x0100_000c);
        assert_eq!(slices[0].data, b"\xcf\xfa\xed\xfe");
    }

    #[test]
    fn pairs_archive_members_and_preserves_added_members() {
        fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
            let mut output = AR_MAGIC.to_vec();
            for (name, contents) in members {
                let name = format!("{name}/");
                let header = format!(
                    "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    "0",
                    "0",
                    "0",
                    "644",
                    contents.len()
                );
                assert_eq!(header.len(), 60);
                output.extend_from_slice(header.as_bytes());
                output.extend_from_slice(contents);
                if !contents.len().is_multiple_of(2) {
                    output.push(b'\n');
                }
            }
            output
        }

        let directory = tempfile::tempdir().unwrap();
        let left = directory.path().join("left.a");
        let right = directory.path().join("right.a");
        fs::write(&left, archive(&[("same.o", b"\x7fELFsame")])).unwrap();
        fs::write(
            &right,
            archive(&[("same.o", b"\x7fELFsame"), ("added.o", b"\x7fELFnew")]),
        )
        .unwrap();

        let analysis = Analysis::open(&left, &right, 8).unwrap();
        assert_eq!(analysis.comparisons.len(), 3);
        assert_eq!(analysis.comparisons[1].label, "same.o");
        assert!(analysis.comparisons[1].left.is_some());
        assert!(analysis.comparisons[1].right.is_some());
        assert_eq!(analysis.comparisons[2].label, "added.o");
        assert!(analysis.comparisons[2].left.is_none());
        assert!(analysis.comparisons[2].right.is_some());
    }
}
