use std::path::PathBuf;

use argh::FromArgs;
use log::Level;

#[derive(Debug, FromArgs)]
#[argh(description = "Smicro SSHD server")]
pub struct Options {
    #[argh(option, description = "level of logging")]
    pub log_level: Option<Level>,

    #[argh(
        option,
        description = "bind IP address",
        default = "String::from(\"0.0.0.0\")"
    )]
    pub listening_address: String,

    #[argh(option, description = "listening port", default = "22")]
    pub port: u16,

    #[argh(
        switch,
        description = "run in single-user-mode: use a single authorized_key file and do not change user"
    )]
    pub single_user_mode: bool,

    #[argh(
        option,
        description = "authorized key file for single-user-mode",
        default = "PathBuf::new()"
    )]
    pub authorized_keys_file: PathBuf,

    #[argh(
        switch,
        description = "receive via stdin the socket path through which the connection will be transferred"
    )]
    pub master_socket: bool,

    #[argh(switch, description = "log to syslog")]
    pub log_to_syslog: bool,

    #[argh(
        option,
        description = "path to the directory containing the host keys",
        default = "<PathBuf as std::str::FromStr>::from_str(\"/etc/smicro\").unwrap()"
    )]
    pub host_keys_dir: PathBuf,

    #[argh(switch, description = "disable strace/no_new_privs/... protections")]
    pub disable_protections: bool,
}
