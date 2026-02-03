use crate::windows::{
    Handle,
    structs::UnicodeString,
    wrappers::{
        nt_user_build_hwnd_list, nt_user_get_class_name, nt_user_internal_get_window_text,
        nt_user_query_window,
    },
};

pub struct Window(Handle);

impl Window {
    /// Creates a [`Window`] struct using an already opened process handle.
    ///
    /// # Safety
    /// The caller must ensure that `handle` is a valid `HWND` (window handle).
    pub unsafe fn from_hwnd(hwnd: Handle) -> Self {
        Self(hwnd)
    }

    pub fn pid(&self) -> u32 {
        nt_user_query_window(self.0, 0)
    }

    pub fn tid(&self) -> u32 {
        nt_user_query_window(self.0, 1)
    }

    pub fn class_name(&self) -> String {
        let buf = [0u16; 256];
        let mut class_name = UnicodeString {
            length: 0,
            max_length: (buf.len() * size_of::<u16>()) as u16,
            buffer: buf.as_ptr(),
        };
        nt_user_get_class_name(self.0, 1, &mut class_name);

        let len = (class_name.length / 2) as usize;
        String::from_utf16_lossy(&buf[..len])
    }

    pub fn title(&self) -> String {
        let mut buf = [0u16; 256];
        let status = nt_user_internal_get_window_text(self.0, buf.as_mut_ptr(), buf.len() as i32);
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }
}

pub struct WindowIterator {
    hwnds: Box<[Handle]>,
}

impl Default for WindowIterator {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowIterator {
    pub fn new() -> Self {
        let hwnds = build_hwnd_list();
        println!("{:?}", hwnds);
        Self {
            hwnds: hwnds.into_boxed_slice(),
        }
    }
}

impl Iterator for WindowIterator {
    type Item = Window;

    fn next(&mut self) -> Option<Self::Item> {
        let hwnds = core::mem::take(&mut self.hwnds);
        let (first, remaining) = hwnds.split_first()?;
        self.hwnds = remaining.into();

        Some(Window(*first))
    }
}

impl ExactSizeIterator for WindowIterator {
    fn len(&self) -> usize {
        self.hwnds.len()
    }
}

fn build_hwnd_list() -> Vec<Handle> {
    println!("gurt");

    let mut len = 0u32;
    nt_user_build_hwnd_list(0, 0, 0, 0, 0, 0, core::ptr::null_mut(), &mut len);

    let mut buf = Vec::<Handle>::with_capacity(len as usize);
    nt_user_build_hwnd_list(
        0usize,
        0usize,
        0,
        0,
        0u32,
        len,
        buf.as_mut_ptr().cast(),
        &mut len,
    );

    buf
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn iter_windows() {
        println!("hello");
        for window in WindowIterator::new() {
            println!("{}", window.title());
        }
    }
}
