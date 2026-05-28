# quicssh-rs

> :smile: **quicssh-rs** is a QUIC proxy that allows to use QUIC to connect to an SSH server without needing to patch the client or the server.

The Debian/RPM packages and release tarballs install the binary as `quicssh-proxy`. The examples below use that name; if you build from source via `cargo build`, the resulting binary is also named `quicssh-proxy`.

`quicssh-rs` is [quicssh](https://github.com/moul/quicssh) rust implementation. It is based on [quinn](https://github.com/quinn-rs/quinn) and [tokio](https://github.com/tokio-rs/tokio)

Why use QUIC? Because SSH is vulnerable in TCP connection environments, and most SSH packets are actually small, so it is only necessary to maintain the SSH connection to use it in any network environment. QUIC is a good choice because it has good weak network optimization and an important feature called connection migration. This means that I can switch Wi-Fi networks freely when remote, ensuring a stable SSH connection.

## Why not mosh?

Because the architecture of mosh requires the opening of many ports to support control and data connections, which is not very user-friendly in many environments. In addition, vscode remote development does not support mosh.

## Architecture

Standard SSH connection

```
┌───────────────────────────────────────┐             ┌───────────────────────┐
│                  bob                  │             │         wopr          │
│ ┌───────────────────────────────────┐ │             │ ┌───────────────────┐ │
│ │           ssh user@wopr           │─┼────tcp──────┼▶│       sshd        │ │
│ └───────────────────────────────────┘ │             │ └───────────────────┘ │
└───────────────────────────────────────┘             └───────────────────────┘
```

---

SSH Connection proxified with QUIC

```
┌───────────────────────────────────────┐             ┌───────────────────────┐
│                  bob                  │             │         wopr          │
│ ┌───────────────────────────────────┐ │             │ ┌───────────────────┐ │
│ │ssh -o ProxyCommand="quicssh-proxy │ │             │ │       sshd        │ │
│ │ client quic://%h:4433"            │ │             │ └───────────────────┘ │
│ │       user@wopr                   │ │             │           ▲           │
│ └───────────────────────────────────┘ │             │           │           │
│                   │                   │             │           │           │
│                process                │             │  tcp to localhost:22  │
│                   │                   │             │           │           │
│                   ▼                   │             │           │           │
│ ┌───────────────────────────────────┐ │             │┌─────────────────────┐│
│ │  quicssh-proxy client wopr:4433   │─┼─quic (udp)─▶│  quicssh-proxy server ││
│ └───────────────────────────────────┘ │             │└─────────────────────┘│
└───────────────────────────────────────┘             └───────────────────────┘
```

## Usage

```console
$ quicssh-proxy -h
A simple ssh server based on quic protocol

Usage: quicssh-proxy <COMMAND>

Commands:
  server  Server
  client  Client
  help    Print this message or the help of the given subcommand(s)

Options:
      --log <LOG_FILE>         Location of log, Default if
      --log-level <LOG_LEVEL>  Log level, Default Error
  -h, --help                   Print help
  -V, --version                Print version
```

### Client

```console
$ quicssh-proxy client -h
Client

Usage: quicssh-proxy client [OPTIONS] <URL>

Arguments:
  <URL>  Server address

Options:
  -b, --bind <BIND_ADDR>  Client address
  -v, --verbose           Show client connection logs on stderr
  -h, --help              Print help
  -V, --version           Print version
```

#### Client SSH Config

```console
╰─$ cat ~/.ssh/config
Host test
    HostName test.test
    User root
    Port 22333
    ProxyCommand /Users/ouyangjun/code/quicssh-rs/target/release/quicssh-proxy client quic://%h:%p

╰─$ ssh test
Last login: Mon May  1 13:32:15 2023 from 127.0.0.1
```

### Server

```console
$ quicssh-proxy server -h
Server

Usage: quicssh-proxy server [OPTIONS]

Options:
  -l, --listen <LISTEN>        Address to listen on [default: 0.0.0.0:4433]
  -p, --proxy-to <PROXY_TO>  Address of the ssh server [default: 127.0.0.1:22]
  -h, --help                   Print help
  -V, --version                Print version
```

## Silent-drop handshake authentication (`QUICSSH_AUTH_SECRET`)

When the server is started with the environment variable `QUICSSH_AUTH_SECRET` set to a shared secret, it requires every incoming QUIC handshake to carry a matching HMAC-derived token (smuggled in the TLS ALPN extension). Packets that don't carry a valid token — including ordinary QUIC scans and probes that don't know the secret — are dropped without any reply, so the listening UDP port is indistinguishable from a closed/filtered port to an outside observer. Tokens rotate on a fixed window so a captured token can't be replayed indefinitely.

To use it, set the same secret on both ends:

```console
# server
QUICSSH_AUTH_SECRET='your-shared-secret' quicssh-proxy server -l 0.0.0.0:4433

# client
QUICSSH_AUTH_SECRET='your-shared-secret' quicssh-proxy client quic://host:4433
```

When `QUICSSH_AUTH_SECRET` is unset on the server, authentication is disabled and the server behaves as a normal QUIC endpoint (responding to handshakes from any client). This relies on a small patch to the vendored `quinn` fork that suppresses Version Negotiation, stateless reset, and Initial CONNECTION_CLOSE responses for unauthenticated peers — without it, the port could still be fingerprinted via standard QUIC protocol responses even though the application-layer handshake would fail.

[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")
