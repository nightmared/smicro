use std::{
    io::{stdin, Read, Write},
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener, UnixStream},
    },
    process::{Command, Stdio},
};

use log::info;
use mio::net::TcpStream;
use nix::unistd::User;
use rand::random;
use smicro_common::{receive_fd_over_socket, send_fd_over_socket, LoopingBuffer};
use smicro_types::{deserialize::DeserializePacket, serialize::SerializePacket};

use crate::{error::Error, state::State};

pub(crate) fn transfer_connection<const SIZE: usize>(
    state: State,
    mut reader_buf: LoopingBuffer<SIZE>,
    mut sender_buf: LoopingBuffer<SIZE>,
    stream: TcpStream,
    username: String,
) -> Result<(), Error> {
    info!("transferring the connection to a new child");
    let mut socket_secret = [0u8; 20];
    for i in 0..socket_secret.len() {
        // generate a printable ascii character
        socket_secret[i] = random::<u8>() % 96 + 32;
    }
    let socket_path = SocketAddr::from_abstract_name(&socket_secret)?;
    let socket = UnixListener::bind_addr(&socket_path)?;

    let mut cmd = Command::new(&std::env::current_exe()?)
        .args(std::env::args().skip(1))
        .arg("--master-socket")
        .stdin(Stdio::piped())
        .spawn()?;

    let mut stdin = cmd.stdin.take().unwrap();
    stdin.write_all(&socket_secret)?;
    stdin.write_all(b"\n")?;

    stdin.write_all(username.as_bytes())?;
    stdin.write_all(b"\n")?;

    cmd.wait()?;

    let (mut slave_stream, _) = socket.accept()?;

    unsafe {
        reader_buf.send_over_socket(&mut slave_stream)?;
        sender_buf.send_over_socket(&mut slave_stream)?;
        send_fd_over_socket(&mut slave_stream, stream)?;
    };
    slave_stream.shutdown(std::net::Shutdown::Both)?;

    state.serialize(&mut stdin)?;

    Ok(())
}

pub(crate) fn receive_connection<const SIZE: usize>() -> Result<
    (
        User,
        State,
        LoopingBuffer<SIZE>,
        LoopingBuffer<SIZE>,
        TcpStream,
    ),
    Error,
> {
    // Retrieve the socket path to receive the fds from the master process
    let mut abstract_addr = String::with_capacity(64);
    let _ = stdin().read_line(&mut abstract_addr)?;
    // drop the newline character
    abstract_addr.pop();

    // username
    let mut username = String::with_capacity(64);
    let _ = stdin().read_line(&mut username)?;
    // drop the newline character
    username.pop();

    // This should almost never fail, considering we just did that operation in the master process
    let user = match User::from_name(&username) {
        Ok(Some(entry)) => entry,
        _ => {
            info!("User {} could not be found, aborting", &username);
            return Err(Error::UnknownUserName);
        }
    };

    let socket_addr = SocketAddr::from_abstract_name(&abstract_addr.as_bytes())?;
    let mut stream = UnixStream::connect_addr(&socket_addr)?;

    let (reader_buf, sender_buf, client_socket) = unsafe {
        let reader_buf = <LoopingBuffer<SIZE>>::receive_over_socket(&mut stream)?;
        let sender_buf = <LoopingBuffer<SIZE>>::receive_over_socket(&mut stream)?;

        let client_socket = receive_fd_over_socket(&mut stream)?;

        (reader_buf, sender_buf, client_socket)
    };

    let mut buf = Vec::new();
    stdin().read_to_end(&mut buf)?;

    let state = match State::deserialize(buf.as_slice()) {
        Err(e) => {
            return Err(e.into());
        }
        Ok((_, state)) => state,
    };

    Ok((user, state, reader_buf, sender_buf, client_socket))
}
