use crate::cli::TrustListArgs;
use crate::domain::trust::TrustedKey;
use crate::ui::logger::{print_json, Logger};
use serde_json::json;

pub fn display_trusted_keys(keys: &[TrustedKey], args: &TrustListArgs, logger: &Logger) {
    if keys.is_empty() {
        logger.info("No trusted keys found.", None);
        return;
    }

    if args.json {
        let json_keys = serde_json::to_value(keys).unwrap_or(json!([]));
        print_json(&json_keys);
    } else {
        logger.info("🔐 Trusted keys:", None);
        for key in keys {
            let org_display = key.org.as_deref().unwrap_or("N/A");
            println!(
                " - {} ({}): {} [{}]",
                key.name, org_display, key.fingerprint, key.verification_status
            );
        }
    }
}
