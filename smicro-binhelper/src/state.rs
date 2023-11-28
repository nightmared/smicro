use std::{
    collections::HashMap,
    fs::{File, ReadDir},
    iter::Peekable,
    path::PathBuf,
};

use log::warn;

use smicro_types::sftp::types::StatusCode;

use crate::types::{Handle, HandleType};

#[derive(Debug)]
pub struct GlobalState {
    handle_counter: usize,
    handles: HashMap<usize, Handle>,
}

impl GlobalState {
    pub fn new() -> Self {
        Self {
            handle_counter: 0,
            handles: HashMap::new(),
        }
    }

    fn insert_handle(&mut self, handle: Handle) -> String {
        let handle_id = self.handle_counter;
        self.handle_counter += 1;

        self.handles.insert(handle_id, handle);

        handle_id.to_string()
    }

    pub fn create_dir_handle(&mut self, name: PathBuf, dir: ReadDir) -> String {
        self.insert_handle(Handle {
            filename: name,
            ty: HandleType::Directory(dir.peekable()),
        })
    }

    pub fn create_file_handle(&mut self, name: PathBuf, file: File) -> String {
        self.insert_handle(Handle {
            filename: name,
            ty: HandleType::File(file),
        })
    }

    pub fn get_handle(&mut self, handle: &str) -> Option<&mut Handle> {
        let idx = match str::parse(handle) {
            Ok(x) => x,
            Err(e) => {
                warn!("Invalid handle {handle:?}, got err {e:?}");
                return None;
            }
        };

        self.handles.get_mut(&idx)
    }

    pub fn get_dir_handle(
        &mut self,
        handle: &str,
    ) -> Result<(&PathBuf, &mut Peekable<ReadDir>), StatusCode> {
        self.get_handle(handle)
            .map_or(
                Err(StatusCode::Failure),
                |Handle { filename, ty }| match ty {
                    HandleType::Directory(ref mut dir) => Ok((filename, dir)),
                    _ => Err(StatusCode::Failure),
                },
            )
    }

    pub fn get_file_handle(&mut self, handle: &str) -> Result<(&PathBuf, &mut File), StatusCode> {
        self.get_handle(handle)
            .map_or(
                Err(StatusCode::Failure),
                |Handle { filename, ty }| match ty {
                    HandleType::File(ref mut file) => Ok((filename, file)),
                    _ => Err(StatusCode::Failure),
                },
            )
    }

    pub fn close_handle(&mut self, handle: &str) -> Result<(), StatusCode> {
        let idx = str::parse(handle).map_err(|_| StatusCode::Failure)?;
        self.handles
            .remove(&idx)
            .ok_or(StatusCode::Failure)
            .map(|_| ())
    }
}
