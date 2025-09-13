use crate::app_config::{SIGMATE_META_FILE, SIGMATE_SBOM_FILE};
use crate::domain::sbom::CycloneDxSbom;
use crate::domain::signature::SignatureMetadata;
use crate::error::AppError;
use ignore::WalkBuilder;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct OrphanReport {
    pub orphan_sig_files: Vec<PathBuf>,
    pub orphan_meta_entries: Vec<PathBuf>,
    pub orphan_sbom_components: Vec<PathBuf>,
}

pub fn scan_orphans(output_dir: &Path, base_dir: &Path) -> Result<OrphanReport, AppError> {
    let mut report = OrphanReport::default();
    if output_dir.is_dir() {
        let mut builder = WalkBuilder::new(output_dir);
        builder
            .standard_filters(false)
            .hidden(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .ignore(false)
            .parents(false);
        for entry in builder.build().flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(rel) = p.strip_prefix(output_dir) {
                    if let Some(file_name) = rel.file_name().and_then(|s| s.to_str()) {
                        if let Some(orig_name) = file_name.strip_suffix(".sig") {
                            let mut original = rel.to_path_buf();
                            original.set_file_name(orig_name);
                            let candidate = base_dir.join(&original);
                            if !candidate.exists() {
                                report.orphan_sig_files.push(p.to_path_buf());
                            }
                        }
                    }
                }
            }
        }
    }
    let meta_path = output_dir.join(SIGMATE_META_FILE);
    if meta_path.is_file() {
        let content = fs::read_to_string(&meta_path).map_err(|e| AppError::Io { path: meta_path.clone(), source: e })?;
        if !content.trim().is_empty() {
            let entries: Vec<SignatureMetadata> = serde_json::from_str(&content)?;
            for e in entries {
                let candidate = base_dir.join(&e.relpath);
                if !candidate.exists() {
                    report.orphan_meta_entries.push(e.relpath.clone());
                }
            }
        }
    }
    let sbom_path = output_dir.join(SIGMATE_SBOM_FILE);
    if sbom_path.is_file() {
        let content = fs::read_to_string(&sbom_path).map_err(|e| AppError::Io { path: sbom_path.clone(), source: e })?;
        if !content.trim().is_empty() {
            let sbom: CycloneDxSbom = serde_json::from_str(&content)?;
            for c in sbom.components {
                let candidate = base_dir.join(&c.bom_ref);
                if !candidate.exists() {
                    report.orphan_sbom_components.push(PathBuf::from(c.bom_ref));
                }
            }
        }
    }
    Ok(report)
}

pub fn prune_orphans(output_dir: &Path, base_dir: &Path, report: &OrphanReport) -> Result<(), AppError> {
    for p in &report.orphan_sig_files {
        if p.starts_with(output_dir) && p.is_file() {
            fs::remove_file(p).map_err(|e| AppError::Io { path: p.clone(), source: e })?;
        }
    }
    let meta_path = output_dir.join(SIGMATE_META_FILE);
    if meta_path.is_file() {
        let content = fs::read_to_string(&meta_path).map_err(|e| AppError::Io { path: meta_path.clone(), source: e })?;
        if !content.trim().is_empty() {
            let mut entries: Vec<SignatureMetadata> = serde_json::from_str(&content)?;
            entries.retain(|e| base_dir.join(&e.relpath).exists());
            if entries.is_empty() {
                fs::remove_file(&meta_path).map_err(|e| AppError::Io { path: meta_path, source: e })?;
            } else {
                let tmp = meta_path.with_extension("json.tmp");
                let data = serde_json::to_string_pretty(&entries)?;
                fs::write(&tmp, data).map_err(|e| AppError::Io { path: tmp.clone(), source: e })?;
                fs::rename(&tmp, &meta_path).map_err(|e| AppError::Io { path: tmp, source: e })?;
            }
        }
    }
    let sbom_path = output_dir.join(SIGMATE_SBOM_FILE);
    if sbom_path.is_file() {
        let content = fs::read_to_string(&sbom_path).map_err(|e| AppError::Io { path: sbom_path.clone(), source: e })?;
        if !content.trim().is_empty() {
            let mut sbom: CycloneDxSbom = serde_json::from_str(&content)?;
            sbom.components.retain(|c| base_dir.join(&c.bom_ref).exists());
            if sbom.components.is_empty() {
                fs::remove_file(&sbom_path).map_err(|e| AppError::Io { path: sbom_path, source: e })?;
            } else {
                let tmp = sbom_path.with_extension("json.tmp");
                let data = serde_json::to_string_pretty(&sbom)?;
                fs::write(&tmp, data).map_err(|e| AppError::Io { path: tmp.clone(), source: e })?;
                fs::rename(&tmp, &sbom_path).map_err(|e| AppError::Io { path: tmp, source: e })?;
            }
        }
    }
    Ok(())
}