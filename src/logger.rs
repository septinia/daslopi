use std::sync::{Arc, Mutex};
use std::io::Write;

pub struct Logger {
    buffer: Arc<Mutex<String>>,
}

impl Logger {
    pub fn new() -> Self {
        Logger {
            buffer: Arc::new(Mutex::new(String::new())),
        }
    }

    pub fn get_logs(&self) -> String {
        let buffer = self.buffer.lock().unwrap();
        buffer.clone()
    }

    pub fn clear_logs(&self) {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.clear();
    }

    pub fn log(&self, message: &str) {
        let mut buffer = self.buffer.lock().unwrap();  // Now this is a synchronous lock
        buffer.push_str(message);
        buffer.push('\n');
    }
}

impl Write for Logger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.push_str(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}