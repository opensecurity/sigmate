use serde_json::Value;

pub struct Logger {
    debug_enabled: bool,
    emojis_enabled: bool,
    json_mode: bool,
}

impl Logger {
    pub fn new(debug_enabled: bool, emojis_enabled: bool) -> Self {
        Self {
            debug_enabled,
            emojis_enabled,
            json_mode: false,
        }
    }

    pub fn set_json_mode(&mut self, json_mode: bool) {
        if json_mode {
            self.debug("JSON output mode enabled, debug logs will be suppressed.", Some("🤫"));
        }
        self.json_mode = json_mode;
    }

    fn log(&self, level: &str, emoji: &str, message: &str) {
        if self.emojis_enabled {
            println!("{} {}", emoji, message);
        } else {
            println!("[{}] {}", level, message);
        }
    }

    pub fn info(&self, message: &str, emoji: Option<&str>) {
        self.log("INFO", emoji.unwrap_or("ℹ️"), message);
    }

    pub fn warn(&self, message: &str, emoji: Option<&str>) {
        self.log("WARN", emoji.unwrap_or("⚠️"), message);
    }

    pub fn error(&self, message: &str, emoji: Option<&str>) {
        eprintln!("{}", self.format_message("ERROR", emoji.unwrap_or("❌"), message));
    }

    pub fn success(&self, message: &str, emoji: Option<&str>) {
        self.log("OK", emoji.unwrap_or("✅"), message);
    }

    pub fn debug(&self, message: &str, emoji: Option<&str>) {
        if self.debug_enabled && !self.json_mode {
            self.log("DEBUG", emoji.unwrap_or("🐛"), message);
        }
    }

    fn format_message(&self, level: &str, emoji: &str, message: &str) -> String {
        if self.emojis_enabled {
            format!("{} {}", emoji, message)
        } else {
            format!("[{}] {}", level, message)
        }
    }
}

pub fn print_json(data: &Value) {
    if let Ok(pretty_json) = serde_json::to_string_pretty(data) {
        println!("{}", pretty_json);
    }
}