extern crate core;

use std::{
    collections::HashMap,

    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use std::fs::FileType;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use clap::Parser;

use anyhow::Result;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use log::{debug, info};
use serde_bytes::ByteBuf;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

use crate::codec::{
    Bitfield, Extension, ExtensionHandshake, ExtensionKind, Flag, Handshake, Message, MetaData,
    WireCodec,
};
use crate::torrent::MetaInfo;

mod codec;
mod torrent;

const CRATE_AUTHOR: &str = env!("CARGO_PKG_AUTHORS");
const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Copy, Clone, Debug)]
struct ClientState {
    choked: bool,
    interested: bool,
}

impl Default for ClientState {
    fn default() -> Self {
        Self { choked: true, interested: false }
    }
}

#[derive(Debug)]
struct Client {
    frame: Framed<TcpStream, WireCodec>,
    addr: SocketAddr,
    torrents: Arc<DashMap<[u8; 20], Vec<u8>>>,
    current_hash: Option<[u8; 20]>,
    remote: ClientState,
    local: ClientState,
}

impl Client {
    const TIMEOUT: Duration = Duration::from_millis(1500);

    pub fn new(tcp_stream: TcpStream, addr: SocketAddr, torrents: Arc<DashMap<[u8; 20], Vec<u8>>>) -> Self {
        Self {
            frame: Framed::new(tcp_stream, WireCodec::default()),
            addr,
            torrents,
            current_hash: None,
            local: ClientState::default(),
            remote: ClientState::default(),
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        loop {
            let message = match tokio::time::timeout(Self::TIMEOUT, self.frame.next()).await {
                Ok(Some(message)) => message?,
                Ok(None) => {
                    break;
                }
                Err(_) => {
                    debug!("[{}] Sending keep alive", self.addr);
                    self.frame.send(Message::KeepAlive).await?;
                    continue;
                }
            };

            match message {
                Message::KeepAlive => {
                    // We're not actually enforcing timeout so...
                }
                Message::Choke => {
                    debug!("[{}] Received choke", self.addr);
                    self.remote.choked = true;
                }
                Message::Unchoke => {
                    debug!("[{}] Received unchoke", self.addr);
                    self.remote.choked = false;
                }
                Message::Interested => {
                    debug!("[{}] Received interested", self.addr);
                    self.remote.interested = true;
                }
                Message::NotInterested => {
                    debug!("[{}] Received not interested", self.addr);
                    self.remote.interested = false;
                }
                Message::Handshake(handshake) => {
                    info!(
                        "[{}] New connection from {:?} => {:?}",
                        self.addr,
                        std::str::from_utf8(&handshake.peer_id),
                        std::str::from_utf8(&handshake.pstr)
                    );

                    self.current_hash = Some(handshake.info_hash);

                    let reply = Handshake {
                        pstrlen: handshake.pstrlen,
                        pstr: handshake.pstr,
                        reserved: [0, 0, 0, 0, 0, 0x10, 0, 0],
                        info_hash: handshake.info_hash,
                        peer_id: *b"-LT1010-123456789010",
                    };
                    self.frame.send(Message::Handshake(reply)).await?;

                    self.frame.send(Message::Bitfield(Bitfield { bits: vec![0b11111000] })).await?;

                    //self.frame.send(Message::Unchoke).await?;
                    self.frame.send(Message::NotInterested).await?;
                    self.local.choked = true;
                }
                Message::Have(have) => {
                    debug!("[{}] Peer indicated that they have piece {}", self.addr, have.index);
                }
                Message::Bitfield(_) => {
                    debug!("[{}] Peer sent bitfield", self.addr);
                }
                Message::Request(request) => {
                    debug!("[{}] Peer requested piece {}", self.addr, request.index);
                }
                Message::Piece(piece) => {
                    debug!("[{}] Received piece {} from peer", self.addr, piece.index);
                }
                Message::Cancel(_) => {
                    debug!("[{}] Peer cancelled their request", self.addr);
                }
                Message::Port(port) => {
                    debug!("[{}] Peers DHT port is {}", self.addr, port.port);
                }
                Message::Unknown(id, _) => {
                    debug!("[{}] Peer sent unknown message type {}", self.addr, id);
                }
                Message::Extension(Extension::Flag(flag)) => {
                    debug!("[{}] Peer sent flag: {}", self.addr, flag.flag);
                }
                Message::Extension(Extension::Handshake(handshake)) => {
                    debug!("[{}] Peer sent extension handshake!", self.addr);

                    let mut options = handshake
                        .m
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(key, value)| {
                            if key.to_lowercase() == "ut_metadata" {
                                if value != 0 {
                                    debug!("Client requested {}, enabling it at {}", key, value);
                                    let codec = self.frame.codec_mut();
                                    codec.extensions.insert(ExtensionKind::MetaData, value);
                                }

                                (key, value)
                            } else if key.to_lowercase() == "ut_flag" {
                                if value != 0 {
                                    debug!("Client requested {}, enabling it at {}", key, value);
                                    let codec = self.frame.codec_mut();
                                    codec.extensions.insert(ExtensionKind::Flag, value);
                                }

                                (key, value)
                            } else {
                                (key, 0)
                            }
                        })
                        .collect::<HashMap<_, _>>();

                    if !options.contains_key("ut_flag") {
                        options.insert("ut_flag".to_string(), 99);
                    }

                    if self.frame.codec().extensions.contains_key(&ExtensionKind::Flag) {
                        self.frame
                            .send(Message::Extension(Extension::Flag(Flag {
                                flag: std::env::var("FLAG").unwrap_or_default(),
                            })))
                            .await?;
                    }

                    let version = format!("{}/{}@{}", CRATE_AUTHOR, CRATE_NAME, CRATE_VERSION);

                    let octets = match self.addr.ip() {
                        IpAddr::V4(ip) => ByteBuf::from(ip.octets()),
                        IpAddr::V6(ip) => ByteBuf::from(ip.octets()),
                    };

                    let metadata_size = self.current_hash.map(|hash| self.torrents.get(&hash)).flatten().map(|info| info.len() as u32);

                    let handshake = ExtensionHandshake {
                        m: Some(options),
                        p: None,
                        v: Some(version),
                        yourip: Some(octets),
                        ipv6: None,
                        ipv4: None,
                        reqq: Some(250),
                        metadata_size,
                    };

                    self.frame.send(Message::Extension(Extension::Handshake(handshake))).await?;
                }
                Message::Extension(Extension::Unknown(id, _)) => {
                    debug!("[{}] Peer sent unknown extension: {}", self.addr, id);
                }
                Message::Extension(Extension::DontHave(donthave)) => {
                    debug!("[{}] Peer no longer has piece: {}", self.addr, donthave.index);
                }
                Message::Extension(Extension::MetaData(metadata)) => match metadata.msg_type {
                    0 => {
                        debug!("[{}] Peer requested metadata piece: {}", self.addr, metadata.piece);
                        let start = metadata.piece as usize * 2_usize.pow(14);
                        let info = self.current_hash.map(|hash| self.torrents.get(&hash)).flatten();

                        match info {
                            Some(info) => {
                                self.frame.send(Message::Extension(Extension::MetaData(MetaData {
                                    msg_type: 1,
                                    piece: metadata.piece,
                                    total_size: Some(info.len()),
                                    data: Some(info.iter().copied().skip(start).take(2_usize.pow(14)).collect()),
                                }))).await?;
                            },
                            None => {
                                self.frame.send(Message::Extension(Extension::MetaData(MetaData {
                                    msg_type: 2,
                                    piece: metadata.piece,
                                    total_size: None,
                                    data: None,
                                }))).await?;
                            }
                        }
                    }
                    1 => {
                        debug!("[{}] Peer sent metadata piece: {}", self.addr, metadata.piece);
                    }
                    2 => {
                        debug!(
                            "[{}] Peer rejected metadata piece request: {}",
                            self.addr, metadata.piece
                        );
                    }
                    _ => {
                        debug!("Unknown metadata request: {}", metadata.msg_type);
                    }
                },
            }
        }
        Ok(())
    }
}

#[derive(Parser, Debug)]
#[clap(version = "1.0", author = "not-jan")]
/// Structure representing command line options for the program.
pub struct Opts {
    /// The IPv4 address that the program should listen on.
    #[clap(
    short = 'l',
    long = "listen-address",
    env = "LISTEN_ADDRESS",
    default_value = "0.0.0.0"
    )]
    pub listen_address: String,

    /// The port that the program should bind to.
    #[clap(short = 'p', long = "port", env = "LISTEN_PORT", default_value = "8082")]
    pub listen_port: u16,

    #[clap(short = 'd', long = "torrent-dir", env = "TORRENT_DIR", default_value = "./torrents")]
    pub torrent_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Opts::parse();
    let ip = Ipv4Addr::from_str(&args.listen_address)?;

    let torrents = Arc::new(DashMap::new());

    for entry in std::fs::read_dir(&args.torrent_dir)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            let data = std::fs::read(entry.path())?;
            let torrent: MetaInfo = serde_bencoded::from_bytes(&data)?;
            let info_hash = torrent.info_hash()?;

            let mut hex = String::with_capacity(40);

            for b in info_hash {
                hex.push_str(&format!("{:02x}", b));
            }

            debug!("Added torrent with the info hash {}", hex);
            let info_data = serde_bencoded::to_vec(&torrent.info)?;
            torrents.insert(info_hash, info_data);

        }
    }


    let tcp_listener = TcpListener::bind((ip, args.listen_port)).await?;
    info!("Server is ready to accept connections on {}:{}", ip, args.listen_port);

    loop {
        // Accept incoming socket connections.
        let (tcp_stream, socket_addr) = tcp_listener.accept().await?;
        let torrents = torrents.clone();
        tokio::spawn(async move {
            let result = Client::new(tcp_stream, socket_addr, torrents).handle().await;
            match result {
                Ok(_) => {
                    info!("[{}] Disconnected", socket_addr.ip());
                }
                Err(error) => match error.downcast::<std::io::Error>() {
                    Ok(io_err) if io_err.kind() == ErrorKind::ConnectionReset => {
                        info!("[{}] Peer disconnected, probably timeout", socket_addr.ip());
                    }
                    Ok(err) => {
                        log::error!("Client::handle() encountered IO error: {}", err);
                    }
                    Err(err) => {
                        log::error!("Client::handle() encountered error: {}", err);
                        debug!("{}", err.backtrace());
                    }
                },
            }
        });
    }
}
