# smicro

## What

A small, monothreaded, mostly safe, executable helper that provides SFTP support for any SSH server (OpenSSH, dropbear, ...).

## Why

* Learning about the SFTP protocol
* Writing some Rust the easy way (no concurrency, no async/await scheduling with `Pin<Box<dyn Future<Output= ...>>>` or `Send/Sync` obsctacles, hence no unexpected hair loss)
* Settling an argument we had at work about the number of lines needed to write a new SFTP helper binary in Rust (the argument was pointless anyway, because we rightly choose not to do that, but that sparked this small project)
* Why not?

## How do I use it?

**Prerequisite**: the target computer/server must be a Linux box!

Build the binary:
```
$ cargo build --target x86_64-unknown-linux-musl --release
```
Copy it to `/usr/libexec`:
```
$ sudo cp target/x86_64-unknown-linux-musl/release/smicro /usr/libexec/smicro-sftp
```

Replace `Subsystem sftp internal-sftp` or `Subsystem sftp /usr/libexec/openssh/sftp-server` in `/etc/ssh/sshd_config` with:
```
Subsystem sftp /usr/libexec/smicro-sftp
```
This will tell OpenSSH to spawn our binary whenever a SFTP channel is opened.

Then restart `sshd`.

And you're done :)

## Why should I use it?

That's a good question.

* You need to modify an sftp server to add/change some behaviour, and this procject is a good base for that, being small and fairly self-contained
* Because you don't trust the SFTP server of OpenSSH (but in that case, good luck finding an SSH server you trust!)
* You like to break your setup in subtle ways and want to see how this is gonna bite you later
