# tokio2-socks5

This implementation is re-construction of [`tokio-socks5`](https://github.com/tokio-rs/tokio-socks5) in order to upgrade [`tokio`](https://tokio.rs/) to version `2.xx.xx` which use standard `Future` features. 

## Usage

First, need to install [`rust`](https://www.rust-lang.org/), then run the server in project directory

```
$ cargo run
   ...
Listening for socks5 proxy connections on 127.0.0.1:1080
```

The binary `tokio2-socks5` for Linux or `tokio-sokcs5.exe` for Windows are in `tokio2-socks5\target\debug`.

Start the binary with listening port as parameter:

```
$  ./tokio2-socks5 0.0.0.0:1080
```

One method for Chrome using socks5 proxy, start the chrome program with parameter:

```
--proxy-server="SOCKS5://127.0.0.1:1080"
```

For example in Windows, run command:

```
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --proxy-server="SOCKS5://127.0.0.1:1080"
```

Another way is duplicating chrome shortcut. Add ` --proxy-server="SOCKS5://127.0.0.1:1080"` in `Target` item of `Shortcut` tab properties.

The server is use `tokio` `lookup_host` which depends on host machine DNS to resolve DNS instead of [`Trust-DNS`](http://trust-dns.org/) used in [`tokio-socks5`](https://github.com/tokio-rs/tokio-socks5).

# License

This project is licensed as [Apache 2.0](https://github.com/libra/libra/blob/master/LICENSE).