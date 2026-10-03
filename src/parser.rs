use nom::{
    do_parse,
    complete,
    named,
    named_args,
    alt,
    tag,
    char,
    take,
    take_until,
};
use drogue_nom_utils::{
    parse_usize,
};

use heapless::String;
use crate::adapter::JoinError;

named!(
    pub ok,
    tag!("OK\r\n")
);

named!(
    pub error,
    tag!("ERROR\r\n")
);

named!(
    pub prompt,
    tag!("> ")
);

#[derive(Debug)]
pub(crate) enum JoinResponse {
    Ok,
    JoinError,
}

// [JOIN   ] drogue,192.168.1.174,0,0
#[rustfmt::skip]
named!(
    pub(crate) join<JoinResponse>,
    do_parse!(
        tag!("[JOIN   ] ") >>
        ssid: take_until!(",") >>
        char!(',') >>
        ip: take_until!(",") >>
        char!(',') >>
        tag!("0,0") >>
        tag!("\r\n") >>
        ok >>
        (
            JoinResponse::Ok
        )
    )
);

// [JOIN   ] drogue
// [JOIN   ] Failed
named!(
    pub(crate) join_error<JoinResponse>,
    do_parse!(
        take_until!( "ERROR" ) >>
        error >>
        (
            JoinResponse::JoinError
        )
    )
);

named!(
    pub(crate) join_response<JoinResponse>,
    do_parse!(
        tag!("\r\n") >>
        response:
        alt!(
              complete!(join)
            | complete!(join_error)
        ) >>
        prompt >>
        (
            response
        )

    )
);

pub(crate) enum ConnectResponse {
    Ok,
    Error,
}


named!(
    pub(crate) connected<ConnectResponse>,
    do_parse!(
        tag!("\r\n") >>
        tag!("[TCP  RC] Connecting to ") >>
        take_until!( "\r\n") >>
        tag!("\r\n") >>
        ok >>
        prompt >>
        (
            ConnectResponse::Ok
        )
    )
);

named!(
    pub(crate) connection_failure<ConnectResponse>,
    do_parse!(
        take_until!( "ERROR" ) >>
        error >>
        (
            ConnectResponse::Error
        )
    )
);

named!(
    pub(crate) connect_response<ConnectResponse>,
    alt!(
        complete!(connected)
        | complete!(connection_failure)
    )
);

#[derive(Debug)]
pub(crate) enum CloseResponse {
    Ok,
    Error,
}

named!(
    pub(crate) closed<CloseResponse>,
    do_parse!(
        tag!("\r\n") >>
        tag!("\r\n") >>
        ok >>
        prompt >>
        (
            CloseResponse::Ok
        )
    )
);

named!(
    pub(crate) close_error<CloseResponse>,
    do_parse!(
        tag!("\r\n") >>
        take_until!( "ERROR" ) >>
        error >>
        prompt >>
        (
            CloseResponse::Error
        )
    )
);

named!(
    pub(crate) close_response<CloseResponse>,
    alt!(
          complete!(closed)
        | complete!(close_error)
    )
);

#[derive(Debug)]
pub(crate) enum LeaveResponse {
    Ok,
    Error,
}

named!(
    pub(crate) left<LeaveResponse>,
    do_parse!(
        tag!("\r\n") >>
        tag!("\r\n") >>
        ok >>
        prompt >>
        (
            LeaveResponse::Ok
        )
    )
);

named!(
    pub(crate) leave_error<LeaveResponse>,
    do_parse!(
        tag!("\r\n") >>
        take_until!( "ERROR" ) >>
        error >>
        prompt >>
        (
            LeaveResponse::Error
        )
    )
);

named!(
    pub(crate) leave_response<LeaveResponse>,
    alt!(
          complete!(left)
        | complete!(leave_error)
    )
);

#[derive(Debug)]
pub(crate) enum WriteResponse {
    Ok(usize),
    Error,
}

named!(
    pub(crate) write_ok<WriteResponse>,
    do_parse!(
        tag!("\r\n") >>
        len: parse_usize >>
        tag!("\r\n") >>
        ok >>
        prompt >>
        (
            WriteResponse::Ok(len)
        )
    )
);

named!(
    pub(crate) write_error<WriteResponse>,
    do_parse!(
        tag!("\r\n") >>
        tag!("-1") >>
        tag!("\r\n") >>
        ok >>
        prompt >>
        (
            WriteResponse::Error
        )
    )
);

named!(
    pub(crate) write_response<WriteResponse>,
    alt!(
          complete!(write_ok)
        | complete!(write_error)
    )
);


#[derive(Debug)]
pub(crate) enum ReadResponse<'a> {
    Ok(&'a [u8]),
    Err,
}

named!(
    pub(crate) read_data<ReadResponse>,
    do_parse!(
        tag!("\r\n") >>
        data: take_until!("\r\nOK\r\n>") >>
        tag!("\r\n") >>
        ok >>
        prompt >>
        (
            ReadResponse::Ok(data)
        )
    )
);

named!(
    pub(crate) read_error<ReadResponse>,
    do_parse!(
        tag!("\r\n") >>
        tag!("-1") >>
        tag!("\r\n") >>
        ok >>
        prompt >>
        (
            ReadResponse::Err
        )
    )
);

// An empty read also comes back as a bare `OK\r\n> `, without the leading `\r\n`
// `read_data` expects. It means no data, not a failed read.
named!(
    pub(crate) read_empty<ReadResponse>,
    do_parse!(
        data: take!(0) >>
        ok >>
        prompt >>
        (
            ReadResponse::Ok(data)
        )
    )
);

named!(
    pub(crate) read_response<ReadResponse>,
    alt!(
          complete!(read_data)
        | complete!(read_error)
        | complete!(read_empty)
    )
);


/// The sender reported by `P?` after a UDP read: the address in the second
/// comma-separated field, the port in the fifth.
pub(crate) fn udp_sender(response: &[u8]) -> Option<([u8; 4], u16)> {
    let text = core::str::from_utf8(response).ok()?;
    let line = text.trim_start_matches(['\r', '\n']).split(['\r', '\n']).next()?;
    let mut fields = line.split(',');
    let address = fields.nth(1)?;
    let port = fields.nth(2)?.parse::<u16>().ok()?;
    let mut ip = [0u8; 4];
    let mut octets = address.split('.');
    for byte in ip.iter_mut() {
        *byte = octets.next()?.parse().ok()?;
    }
    if octets.next().is_some() {
        return None;
    }
    Some((ip, port))
}

#[cfg(test)]
mod udp_sender_tests {
    use super::{read_response, udp_sender, ReadResponse};

    #[test]
    fn a_bare_ok_is_an_empty_read() {
        for reply in [&b"OK\r\n> "[..], b"\r\n\r\nOK\r\n> "] {
            match read_response(reply) {
                Ok((_, ReadResponse::Ok(data))) => assert!(data.is_empty()),
                _ => panic!("{reply:?} did not parse as an empty read"),
            }
        }
        match read_response(b"\r\nabc\r\nOK\r\n> ") {
            Ok((_, ReadResponse::Ok(data))) => assert_eq!(data, b"abc"),
            _ => panic!("data read did not parse"),
        }
    }

    #[test]
    fn reads_the_sender_fields() {
        let reply = b"\r\n1,192.168.1.94,0,192.168.1.94,13001,0,0,1,0,0,0,7200000\r\nOK\r\n> ";
        assert_eq!(udp_sender(reply), Some(([192, 168, 1, 94], 13001)));
        let reply = b"\r\n1,64.131.47.178,0,64.131.47.178,123,0,0,1,0,0,0,7200000\r\nOK\r\n> ";
        assert_eq!(udp_sender(reply), Some(([64, 131, 47, 178], 123)));
    }

    #[test]
    fn rejects_malformed_replies() {
        assert_eq!(udp_sender(b"\r\nERROR\r\n> "), None);
        assert_eq!(udp_sender(b"\r\n1,1.2.3,0,1.2.3.4,5\r\n"), None);
    }
}
