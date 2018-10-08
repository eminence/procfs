use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use libc;

use {ProcError, ProcResult};

pub fn read_file<P: AsRef<Path>>(path: P) -> ProcResult<String> {
    let mut f = File::open(path)?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf)
}

pub fn write_file<P: AsRef<Path>, T: AsRef<[u8]>>(path: P, buf: T) -> ProcResult<()> {
    let mut f = File::open(path)?;
    f.write_all(buf.as_ref())?;
    Ok(())
}

pub fn read_value<P: AsRef<Path>, T: FromStr<Err = E>, E: fmt::Debug>(path: P) -> ProcResult<T> {
    read_file(path).map(|buf| buf.trim().parse().unwrap())
}

pub fn write_value<P: AsRef<Path>, T: fmt::Display>(path: P, value: T) -> ProcResult<()> {
    write_file(path, value.to_string().as_bytes())
}

pub fn access<P: AsRef<Path>>(path: P, mode: i32) -> bool {
    unsafe {
        libc::access(
            CString::new(path.as_ref().as_os_str().as_bytes())
                .unwrap()
                .as_ptr(),
            mode,
        ) == 0
    }
}

pub trait Readable<T, E>
where
    T: FromStr<Err = E>,
    E: fmt::Debug,
{
    fn read<P: AsRef<Path>>(path: P) -> ProcResult<T> {
        let path = path.as_ref();

        if access(path, libc::R_OK) {
            read_value(path)
        } else {
            Err(ProcError::PermissionDenied)
        }
    }
}

pub trait Writeable<T>
where
    T: fmt::Display,
{
    fn write<P: AsRef<Path>>(path: P, value: T) -> ProcResult<()> {
        let path = path.as_ref();

        if access(path, libc::W_OK) {
            write_value(path, value)
        } else {
            Err(ProcError::PermissionDenied)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReadOnly {}

impl<T, E> Readable<T, E> for ReadOnly
where
    T: FromStr<Err = E>,
    E: fmt::Debug,
{
}

#[derive(Clone, Copy, Debug)]
pub struct WriteOnly {}

impl<T> Writeable<T> for WriteOnly where T: fmt::Display {}

#[derive(Clone, Copy, Debug)]
pub struct ReadWrite {}

impl<T, E> Readable<T, E> for ReadWrite
where
    T: FromStr<Err = E>,
    E: fmt::Debug,
{
}

impl<T> Writeable<T> for ReadWrite where T: fmt::Display {}

#[derive(Clone, Debug)]
pub struct Value<T, M> {
    path: PathBuf,
    phantom: PhantomData<(T, M)>,
}

impl<T, M> Value<T, M> {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Value {
            path: path.into(),
            phantom: PhantomData,
        }
    }
}

impl<T, E, M> Value<T, M>
where
    T: FromStr<Err = E>,
    E: fmt::Debug,
    M: Readable<T, E>,
{
    pub fn readable(&self) -> bool {
        access(&self.path, libc::R_OK)
    }

    pub fn get(&self) -> ProcResult<T> {
        M::read(&self.path)
    }
}

impl<T, M> Value<T, M>
where
    T: fmt::Display,
    M: Writeable<T>,
{
    pub fn writeable(&self) -> bool {
        access(&self.path, libc::W_OK)
    }

    pub fn set(&self, value: T) -> ProcResult<()> {
        M::write(&self.path, value)
    }
}

#[macro_export]
macro_rules! procfs_value {
    (__impl $(#[$attr:meta])* $name:ident : $ty:ty ; $mode:ident) => {
        $(#[$attr])*
        pub fn $name() -> ProcResult<$crate::value::Value<$ty, $crate::value::$mode>> {
            let path = module_path!().trim_left_matches("procfs::").replace("::", "/");
            let path = ::std::path::Path::new("/proc").join(path).join(stringify!($name));

            if path.exists() {
                Ok($crate::value::Value::new(path))
            } else {
                Err($crate::ProcError::NotFound)
            }
        }
    };
    ($(#[$attr:meta])* @readwrite $name:ident : $ty:ty ; $($rest:tt)*) => {
        procfs_value!(__impl $(#[$attr])* $name : $ty ; ReadWrite);
        procfs_value!($($rest)*);
    };
    ($(#[$attr:meta])* @readonly $name:ident : $ty:ty ; $($rest:tt)*) => {
        procfs_value!(__impl $(#[$attr])* $name : $ty ; ReadOnly);
        procfs_value!($($rest)*);
    };
    ($(#[$attr:meta])* @writeonly $name:ident : $ty:ty ; $($rest:tt)*) => {
        procfs_value!(__impl $(#[$attr])* $name : $ty ; WriteOnly);
        procfs_value!($($rest)*);
    };
    ($(#[$attr:meta])* $name:ident : $ty:ty ; $($rest:tt)*) => {
        procfs_value!(__impl $(#[$attr])* $name : $ty ; ReadWrite);
        procfs_value!($($rest)*);
    };
    () => {}
}
