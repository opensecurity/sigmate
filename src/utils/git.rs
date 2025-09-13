use crate::domain::signature::GitInfo;
use crate::error::AppError;
use git2::{DescribeFormatOptions, DescribeOptions, Repository};
use std::collections::HashMap;
use std::path::Path;

pub fn get_git_info_object(
    base_dir: &Path,
) -> Result<Option<HashMap<String, GitInfo>>, AppError> {
    match Repository::discover(base_dir) {
        Ok(repo) => {
            let remote_url = repo
                .find_remote("origin")
                .ok()
                .and_then(|remote| remote.url().map(String::from));

            let git_ref = repo
                .describe(DescribeOptions::new().describe_all())
                .and_then(|d| d.format(Some(DescribeFormatOptions::new().dirty_suffix("-dirty"))))
                .or_else(|_| {
                    repo.head().and_then(|head| {
                        head.shorthand()
                            .map(String::from)
                            .ok_or_else(|| git2::Error::from_str("Failed to get shorthand"))
                    })
                })
                .ok();

            let mut git_map = HashMap::new();
            git_map.insert("git".to_string(), GitInfo { url: remote_url, r#ref: git_ref });
            Ok(Some(git_map))
        }
        Err(_) => Ok(None),
    }
}

pub fn get_git_author(base_dir: &Path) -> Result<Option<String>, AppError> {
    match Repository::discover(base_dir) {
        Ok(repo) => {
            let config = repo.config()?;
            let name = config.get_string("user.name")?;
            let email = config.get_string("user.email")?;
            Ok(Some(format!("{} <{}>", name, email)))
        }
        Err(_) => Ok(None),
    }
}