#![warn(rust_2018_idioms)]

use ::log::{debug, error, info};
use env_logger;
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str;
use tokio;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    lookup_host,
    tcp::{ReadHalf, WriteHalf},
    TcpListener, TcpStream,
};
use tokio::stream::StreamExt;
use tokio::time::{delay_for, Duration};

use futures::{future, FutureExt, TryFutureExt};

#[tokio::main]
async fn main() -> io::Result<()> {
    drop(env_logger::init());

    // Take the first command line argument as an address to listen on, or fall
    // back to just some localhost default.
    let addr = env::args().nth(1).unwrap_or("127.0.0.1:1080".to_string());
    let addr = addr.parse::<SocketAddr>().unwrap();

    // Initialize the various data structures we're going to use in our server.
    // Here we create the event loop, the global buffer that all threads will
    // read/write into, and the bound TCP listener itself.

    let mut listener = TcpListener::bind(&addr).await?;

    // This is the address of the DNS server we'll send queries to. If
    // external servers can't be used in your environment, you can substitue
    // your own.
    // let dns = "8.8.8.8:53".parse().unwrap();
    // let client = UdpClientStream::<UdpSocket>::new(dns);
    // let (bg, mut client) = ClientFuture::connect(client);

    // Construct a future representing our server. This future processes all
    // incoming connections and spawns a new task for each client which will do
    // the proxy work.
    //
    // This essentially means that for all incoming connections, those received
    // from `listener`, we'll create an instance of `Client` and convert it to a
    // future representing the completion of handling that client. This future
    // itself is then *spawned* onto the event loop to ensure that it can
    // progress concurrently with all other connections.
    println!("Listening for socks5 proxy connections on {}", addr);
    let mut incoming = listener.incoming();

    while let Some(Ok(stream)) = incoming.next().await {
        let peer_addr = stream.peer_addr()?;
        tokio::spawn(async move {
            let mut client = Client {};

            match client.serve(stream).await {
                Ok((a, b, addr)) => {
                    info!("proxied {} --> {}: {}/{} bytes", peer_addr, *addr, a, b,)
                }
                Err(e) => error!("error for {}: {}", peer_addr, e),
            };

            io::Result::Ok(())
        });
    }

    Ok(())
}

// Data used to when processing a client to perform various operations over its
// lifetime.
struct Client {}

impl Client {
    /// This is the main entry point for starting a SOCKS proxy connection.
    ///
    /// This function is responsible for constructing the future which
    /// represents the final result of the proxied connection. In this case
    /// we're going to return an `IoFuture<T>`, an alias for
    /// `Future<Item=T, Error=io::Error>`, which indicates how many bytes were
    /// proxied on each half of the connection.
    ///
    /// The first part of the SOCKS protocol with a remote connection is for the
    /// server to read one byte, indicating the version of the protocol. The
    /// `read_exact` combinator is used here to entirely fill the specified
    /// buffer, and we can use it to conveniently read off one byte here.
    ///
    /// Once we've got the version byte, we then delegate to the below
    /// `serve_vX` methods depending on which version we found.
    async fn serve(&mut self, mut conn: TcpStream) -> io::Result<(u64, u64, Box<String>)> {
        let mut buf = [0u8; 1];

        conn.read_exact(&mut buf).await?;
        let res = match buf[0] {
            v5::VERSION => self.serve_v5(conn).await,
            v4::VERSION => self.serve_v4(conn),

            // If we hit an unknown version, we return a "terminal future"
            // which represents that this future has immediately failed. In
            // this case the type of the future is `io::Error`, so we use a
            // helper function, `other`, to create an error quickly.
            n => Err(other(&format!("unknown version {}", n))),
        };
        res
    }

    async fn serve_v5(&mut self, mut conn: TcpStream) -> io::Result<(u64, u64, Box<String>)> {
        // First part of the SOCKSv5 protocol is to negotiate a number of
        // "methods". These methods can typically be used for various kinds of
        // proxy authentication and such, but for this server we only implement
        // the `METH_NO_AUTH` method, indicating that we only implement
        // connections that work with no authentication.
        //
        // First here we do the same thing as reading the version byte, we read
        // a byte indicating how many methods. Afterwards we then read all the
        // methods into a temporary buffer.
        //
        // Note that we use `and_then` here to chain computations after one
        // another, but it also serves to simply have fallible computations,
        // such as checking whether the list of methods contains `METH_NO_AUTH`.
        let num_methods = async move {
            let mut buf = [0u8; 1];
            conn.read_exact(&mut buf).await?;
            io::Result::Ok((buf, conn))
        }
        .boxed();

        let authenticated = num_methods
            .and_then(|(buf, mut conn)| {
                async move {
                    let mut buf = vec![0u8; buf[0] as usize];
                    let _ = conn.read_exact(&mut buf).await?;
                    if buf.contains(&v5::METH_NO_AUTH) {
                        io::Result::Ok(conn)
                    } else {
                        io::Result::Err(other("no supported method given"))
                    }
                }
            })
            .boxed();

        // After we've concluded that one of the client's supported methods is
        // `METH_NO_AUTH`, we "ack" this to the client by sending back that
        // information. Here we make use of the `write_all` combinator which
        // works very similarly to the `read_exact` combinator.
        let part1 = authenticated
            .and_then(|mut conn| {
                async move {
                    conn.write_all(&[v5::VERSION, v5::METH_NO_AUTH]).await?;
                    io::Result::Ok(conn)
                }
            })
            .boxed();

        // Next up, we get a selected protocol version back from the client, as
        // well as a command indicating what they'd like to do. We just verify
        // that the version is still v5, and then we only implement the
        // "connect" command so we ensure the proxy sends that.
        //
        // As above, we're using `and_then` not only for chaining "blocking
        // computations", but also to perform fallible computations.
        let ack = part1
            .and_then(|mut conn| {
                async move {
                    let mut buf = [0u8; 1];
                    let _ = conn.read_exact(&mut buf).await?;
                    if buf[0] == v5::VERSION {
                        io::Result::Ok(conn)
                    } else {
                        io::Result::Err(other("didn't confirm with v5 version"))
                    }
                }
            })
            .boxed();

        let command = ack
            .and_then(|mut conn| {
                async move {
                    let mut buf = [0u8; 1];
                    let _ = conn.read_exact(&mut buf).await?;
                    if buf[0] == v5::CMD_CONNECT {
                        io::Result::Ok(conn)
                    } else {
                        io::Result::Err(other("unsupported command"))
                    }
                }
            })
            .boxed();

        // After we've negotiated a command, there's one byte which is reserved
        // for future use, so we read it and discard it. The next part of the
        // protocol is to read off the address that we're going to proxy to.
        // This address can come in a number of forms, so we read off a byte
        // which indicates the address type (ATYP).
        //
        // Depending on the address type, we then delegate to different futures
        // to implement that particular address format.
        let atyp = command
            .and_then(|mut conn| {
                async move {
                    let mut buf = [0u8; 1];
                    conn.read_exact(&mut buf).await?;
                    conn.read_exact(&mut buf).await?;
                    io::Result::Ok((buf, conn))
                }
            })
            .boxed();

        let addr = atyp
            .and_then(|(buf, mut conn)| {
                async move {
                    match buf[0] {
                        // For IPv4 addresses, we read the 4 bytes for the address as
                        // well as 2 bytes for the port.
                        v5::ATYP_IPV4 => {
                            let mut buf = [0u8; 6];
                            conn.read_exact(&mut buf).await?;
                            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                            let addr = SocketAddrV4::new(addr, port);
                            Ok((SocketAddr::V4(addr), conn, Box::new(addr.to_string())))
                        }

                        v5::ATYP_IPV6 => {
                            let mut buf = [0u8; 18];
                            conn.read_exact(&mut buf).await?;
                            let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                            let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                            let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                            let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                            let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                            let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                            let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                            let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                            let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                            let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                            let addr = SocketAddrV6::new(addr, port, 0, 0);
                            Ok((SocketAddr::V6(addr), conn, Box::new(addr.to_string())))
                        }
                        // The SOCKSv5 protocol not only supports proxying to specific
                        // IP addresses, but also arbitrary hostnames. This allows
                        // clients to perform hostname lookups within the context of the
                        // proxy server rather than the client itself.
                        //
                        // Since the first publication of this code, several
                        // futures-based DNS libraries appeared, and as a demonstration
                        // of integrating third-party asynchronous code into our chain,
                        // we will use one of them, TRust-DNS.
                        //
                        // The protocol here is to have the next byte indicate how many
                        // bytes the hostname contains, followed by the hostname and two
                        // bytes for the port. To read this data, we execute two
                        // respective `read_exact` operations to fill up a buffer for
                        // the hostname.
                        //
                        // Finally, to perform the "interesting" part, we process the
                        // buffer and pass the retrieved hostname to a query future if
                        // it wasn't already recognized as an IP address. The query is
                        // very basic: it asks for an IPv4 address with a timeout of
                        // five seconds. We're using TRust-DNS at the protocol level,
                        // so we don't have the functionality normally expected from a
                        // stub resolver, such as sorting of answers according to RFC
                        // 6724, more robust timeout handling, or resolving CNAME
                        // lookups.
                        v5::ATYP_DOMAIN => {
                            let mut buf = [0u8; 1];
                            conn.read_exact(&mut buf).await?;
                            let mut buf = vec![0u8; (buf[0] as usize) + 2];
                            conn.read_exact(&mut buf).await?;
                            let (socket_addr, addr) = name_port(&buf).await?;
                            Ok((socket_addr, conn, addr))
                        }

                        n => {
                            let msg = format!("unknown ATYP received: {}", n);
                            io::Result::Err(other(&msg))
                        }
                    }
                }
            })
            .boxed();

        // Now that we've got a socket address to connect to, let's actually
        // create a connection to that socket!
        //
        // To do this, we use our `handle` field, a handle to the event loop, to
        // issue a connection to the address we've figured out we're going to
        // connect to. Note that this `tcp_connect` method itself returns a
        // future resolving to a `TcpStream`, representing how long it takes to
        // initiate a TCP connection to the remote.
        //
        // We wait for the TCP connect to get fully resolved before progressing
        // to the next stage of the SOCKSv5 handshake, but we keep a hold of any
        // possible error in the connection phase to handle it in a moment.
        let connected = addr
            .and_then(|(socket_addr, conn, dest_addr)| {
                async move {
                    debug!("proxying to {}", socket_addr);
                    Ok((conn, TcpStream::connect(socket_addr).await, dest_addr))
                }
            })
            .boxed();

        // Once we've gotten to this point, we're ready for the final part of
        // the SOCKSv5 handshake. We've got in our hands (c2) the client we're
        // going to proxy data to, so we write out relevant information to the
        // original client (c1) the "response packet" which is the final part of
        // this handshake.
        let handshake_finish = connected
            .and_then(|(mut conn, c2, dest_addr)| {
                async move {
                    let mut resp = [0u8; 32];

                    // VER - protocol version
                    resp[0] = 5;

                    // REP - "reply field" -- what happened with the actual connect.
                    //
                    // In theory this should reply back with a bunch more kinds of
                    // errors if possible, but for now we just recognize a few concrete
                    // errors.
                    resp[1] = match c2 {
                        Ok(..) => 0,
                        Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                        Err(..) => 1,
                    };

                    // RSV - reserved
                    resp[2] = 0;

                    // ATYP, BND.ADDR, and BND.PORT
                    //
                    // These three fields, when used with a "connect" command
                    // (determined above), indicate the address that our proxy
                    // connection was bound to remotely. There's a variable length
                    // encoding of what's actually written depending on whether we're
                    // using an IPv4 or IPv6 address, but otherwise it's pretty
                    // standard.
                    let addr = match c2.as_ref().map(|r| r.local_addr()) {
                        Ok(Ok(addr)) => Ok(addr),
                        Ok(Err(e)) => io::Result::Err(e),
                        Err(e) => io::Result::Err(io::Error::new(e.kind(), e.to_string().as_str())),
                    }?;

                    let pos = match addr {
                        SocketAddr::V4(ref a) => {
                            resp[3] = 1;
                            resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                            8
                        }
                        SocketAddr::V6(ref a) => {
                            resp[3] = 4;
                            let mut pos = 4;
                            for &segment in a.ip().segments().iter() {
                                resp[pos] = (segment >> 8) as u8;
                                resp[pos + 1] = segment as u8;
                                pos += 2;
                            }
                            pos
                        }
                    };

                    resp[pos] = (addr.port() >> 8) as u8;
                    resp[pos + 1] = addr.port() as u8;

                    // Slice our 32-byte `resp` buffer to the actual size, as it's
                    // variable depending on what address we just encoding. Once that's
                    // done, write out the whole buffer to our client.
                    //
                    // The returned type of the future here will be `(TcpStream,
                    // TcpStream)` representing the client half and the proxy half of
                    // the connection.
                    conn.write_all(&resp[..(pos + 2)]).await?;
                    io::Result::Ok((conn, c2?, dest_addr))
                }
            })
            .boxed();

        // Phew! If you've gotten this far, then we're now entirely done with
        // the entire SOCKSv5 handshake!
        //
        // In order to handle ill-behaved clients, however, we have an added
        // feature here where we'll time out any initial connect operations
        // which take too long.
        //
        // Here we create a timeout future, using the `Timeout::new` method,
        // which will create a future that will resolve to `()` in 10 seconds.
        // We then apply this timeout to the entire handshake all at once by
        // performing a `select` between the timeout and the handshake itself.
        let delay = delay_for(Duration::new(20, 0));
        let pair = future::select(handshake_finish, delay)
            .then(|either| {
                async move {
                    match either {
                        future::Either::Left((Ok(pair), _)) => Ok(pair),
                        future::Either::Left((Err(e), _)) => Err(e),
                        future::Either::Right(((), _)) => {
                            io::Result::Err(other("timeout during handshake"))
                        }
                    }
                }
            })
            .boxed();

        // At this point we've *actually* finished the handshake. Not only have
        // we read/written all the relevant bytes, but we've also managed to
        // complete in under our allotted timeout.
        //
        // At this point the remainder of the SOCKSv5 proxy is shuttle data back
        // and for between the two connections. That is, data is read from `c1`
        // and written to `c2`, and vice versa.
        //
        // To accomplish this, we put both sockets into their own `Rc` and then
        // create two independent `Transfer` futures representing each half of
        // the connection. These two futures are `join`ed together to represent
        // the proxy operation happening.
        pair.and_then(|(mut c1, mut c2, dest_addr)| {
            async move {
                let (c1_read, c1_write) = c1.split();
                let (c2_read, c2_write) = c2.split();

                let half1 = transfer(c1_read, c2_write);
                let half2 = transfer(c2_read, c1_write);
                let (res1, res2) = future::try_join(half1, half2).await?;
                io::Result::Ok((res1, res2, dest_addr))
            }
        })
        .await
    }

    fn serve_v4(&mut self, mut _conn: TcpStream) -> io::Result<(u64, u64, Box<String>)> {
        Err(other("Socks version 4 not implemented"))
    }
}

/// A transfer representing reading all data from one side of a proxy connection
/// and writing it to another. Use async transfer instead of Transfer Future to
/// avoid complicated polling process.
///

async fn transfer(mut reader: ReadHalf<'_>, mut writer: WriteHalf<'_>) -> io::Result<u64> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut amt = 0 as u64;
    loop {
        let read_size = match reader.read(&mut buf).await {
            Ok(n) => {
                if n == 0 {
                    if let Err(e) = writer.shutdown().await {
                        debug!(
                            "shutdown {} error: {}",
                            writer.as_ref().peer_addr().unwrap(),
                            e
                        );
                    }
                    return Ok(amt);
                } else {
                    n
                }
            }
            Err(e) => {
                debug!(
                    "Read from {} error: {}",
                    (reader).as_ref().peer_addr().unwrap(),
                    e
                );
                if let Err(e) = writer.shutdown().await {
                    debug!(
                        "shutdown {} error: {}",
                        writer.as_ref().peer_addr().unwrap(),
                        e
                    );
                }
                return Ok(amt);
            }
        };

        const MAX_LEN: usize = 1024 * 1024 * 10;

        if read_size >= buf.len() && buf.len() <= MAX_LEN {
            buf.resize_with(buf.len() * 2, Default::default);
            debug!(
                "Expand the read buffer size to {} for {}",
                buf.len(),
                reader.as_ref().peer_addr().unwrap()
            );
        }
        if let Err(e) = writer.write_all(&buf[..read_size]).await {
            debug!(
                "Write to {} error: {}",
                writer.as_ref().peer_addr().unwrap(),
                e
            );
            if let Err(e) = writer.shutdown().await {
                debug!(
                    "shutdown {} error: {}",
                    writer.as_ref().peer_addr().unwrap(),
                    e
                );
            }
            return Ok(amt);
        }

        amt += read_size as u64;
    }
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

// Extracts the name and port from addr_buf and returns them, converting
// the name to the form that the trust-dns client can use. If the original
// name can be parsed as an IP address, makes a SocketAddr from that
// address and the port and returns it; we skip DNS resolution in that
// case.
async fn name_port(addr_buf: &[u8]) -> io::Result<(SocketAddr, Box<String>)> {
    // The last two bytes of the buffer are the port, and the other parts of it
    // are the hostname.
    let hostname = &addr_buf[..addr_buf.len() - 2];
    let hostname = str::from_utf8(hostname)
        .map_err(|_e| other("hostname buffer provided was not valid utf-8"))?;
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);
    let dest_addr = format!("{}:{}", hostname, port);

    if let Ok(ip) = hostname.parse() {
        return Ok((SocketAddr::new(ip, port), Box::new(dest_addr)));
    }
    debug!("lookup_host {}", hostname);
    let hostname = &format!("{}:{}", hostname, port);
    let mut addrs = lookup_host(hostname).await?;
    debug!("lookup_host {} success", hostname);
    let first = addrs
        .next()
        .ok_or(other(&format!("wrong hostname {}", hostname)))?;
    Ok((SocketAddr::new(first.ip(), port), Box::new(dest_addr)))
}

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

#[allow(dead_code)]
mod v4 {
    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
}
