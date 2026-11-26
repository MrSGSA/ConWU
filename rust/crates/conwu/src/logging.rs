//! Bounded persistent journal shared by the UI and local diagnostic files.
use crate::store::Store;
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::Write,
    sync::Mutex,
};

pub struct Journal {
    path: std::path::PathBuf,
    inner: Mutex<(VecDeque<Value>, Option<File>)>,
}
impl Journal {
    pub fn open(store: &Store) -> Result<Self> {
        let path = store.checked_file("conwu.log.jsonl")?;
        let mut entries = VecDeque::new();
        store.checked_file("conwu.log.jsonl.previous")?;
        if path.is_file() && std::fs::metadata(&path)?.len() <= 4 * 1024 * 1024 {
            for line in std::fs::read_to_string(&path)?.lines() {
                if let Ok(mut row) = serde_json::from_str::<Value>(line) {
                    if let Some(text) = row["text"].as_str() {
                        row["text"] = json!(redact(text));
                        entries.push_back(row);
                        if entries.len() > 250 {
                            entries.pop_front();
                        }
                    }
                }
            }
        }
        let file = open(&path)?;
        Ok(Self {
            path,
            inner: Mutex::new((entries, Some(file))),
        })
    }
    pub fn rows(&self) -> Vec<Value> {
        self.inner.lock().unwrap().0.iter().cloned().collect()
    }
    pub fn push(&self, level: &str, message: &str) {
        let text = redact(message);
        match level {
            "ERROR" => tracing::error!("{text}"),
            "WARN" => tracing::warn!("{text}"),
            "DEBUG" => tracing::debug!("{text}"),
            _ => tracing::info!("{text}"),
        }
        let row = json!({"id":conwu_core::id(),"timestamp":conwu_core::unix_seconds()*1000,"text":format!("[{level}] {text}")});
        self.append(row);
    }
    pub fn punch_summary(&self, summary: Value) {
        let text = format!("[INFO] 打洞 {} {} {} / {}", summary["round"].as_str().unwrap_or(""),
            summary["flow"].as_str().unwrap_or(""), summary["last_stage"].as_str().unwrap_or(""),
            summary["close_reason"].as_str().unwrap_or(""));
        tracing::info!("{text}");
        self.append(json!({"id":conwu_core::id(), "timestamp":conwu_core::unix_seconds()*1000,
            "text":text, "punch":summary}));
    }
    fn append(&self, row: Value) {
        let mut inner = self.inner.lock().unwrap();
        inner.0.push_back(row.clone());
        if inner.0.len() > 250 {
            inner.0.pop_front();
        }
        if inner
            .1
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .is_some_and(|m| m.len() >= 4 * 1024 * 1024)
        {
            inner.1.take();
            let previous = self.path.with_extension("jsonl.previous");
            if !previous.exists()
                || !std::fs::symlink_metadata(&previous).is_ok_and(|m| m.file_type().is_symlink())
            {
                let _ = std::fs::remove_file(&previous);
                let _ = std::fs::rename(&self.path, &previous);
            }
            inner.1 = open(&self.path).ok();
        }
        if let Some(file) = inner.1.as_mut() {
            if let Ok(mut bytes) = serde_json::to_vec(&row) {
                bytes.push(b'\n');
                let _ = file.write_all(&bytes);
                let _ = file.flush();
            }
        }
    }
}
fn open(path: &std::path::Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
pub fn redact(message: &str) -> String {
    let mut out = String::new();
    let mut credential = false;
    for word in message.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        if credential {
            out.push_str("[已隐藏凭据]");
            credential = false;
        } else if let Some(index) = ["https://", "http://", "pkarr://", "SL4.", "SL6.", "SL7."]
            .iter()
            .filter_map(|s| word.find(s))
            .min()
        {
            out.push_str(&word[..index]);
            out.push_str("[已隐藏私密链接]");
        } else if word.len() > 256
            || word.to_ascii_lowercase().contains("bearer")
            || word.to_ascii_lowercase().contains("privatekey")
        {
            out.push_str("[已隐藏凭据]");
            credential = word.eq_ignore_ascii_case("bearer");
        } else {
            out.push_str(word);
        }
        if out.len() >= 2048 {
            out.truncate(out.floor_char_boundary(2048));
            break;
        }
    }
    out
}
#[cfg(test)]
mod tests {
    #[test]
    fn secrets_and_newlines_are_not_persisted() {
        let message =
            super::redact("连接失败\n(https://host.example/private?token=hidden) SL7.secret");
        assert!(
            !message.contains("hidden") && !message.contains("SL7.") && !message.contains('\n')
        );
        assert!(!super::redact("Authorization: Bearer abcdef123456").contains("abcdef"));
    }
}
