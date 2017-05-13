# SockstPy
SockstPy is a Python package that provides SOCKS protocol functionality.

## Features
- Support on both SOCKS4 and SOCK5
- Parsing and generating SOCKS messages
- SOCKS server
- Basic SOCKS client with CONNECT and UDP ASSOCIATE
- Python socket with SOCKS client capabilities (CONNECT, BIND and UDP ASSOCIATE supported)
- Connecting to chains of SOCKS server supported on the basic client and can be written with the SOCKS socket
- Reverse connection suppurted on the server, the basic client and the SOCKS socket
- Command line execution for the SOCKS server and the basic client

## Prerequisites
Python 2.10 or greater (could work on python 2.9 but not tested yet).
Does not support python 3.

## Installation
Download the package and:
```
python setup.py install
```

## Usage
Modules in this package:
- Socks- for parsing and generating SOCKS messages.
- SockSocket- A Python SOCKS client module inherits from python standard socket
- SockServer- SOCKS server module
- SocksClient- A basic SOCKS client 

### Socks

```
>>> import sockstpy
>>> from sockstpy import socks
>>> soc = socks(5)
>>> soc.generate_request(sockstpy.CMD_CONNECT, "127.0.0.1", 1080, sockstpy.ADD_IPV4)
'\x05\x01\x00\x01\x7f\x00\x00\x01\x048'
>>> soc.parse_request(_)
(1, 1, '127.0.0.1', 1080)
>>> soc.generate_udp(0, "hostname", 53, sockstpy.ADD_DOMAIN, "datagram here")
'\x00\x00\x00\x03\x08hostname\x005datagram here'
>>> soc.parse_udp(_)
(0, 3, 'hostname', 53, 'datagram here')
```

### SockSocket
The idea of SockSocket module inspired by [PySocks](https://github.com/Anorov/PySocks) (written by @anorov) and by [SocksiPy](http://socksipy.sourceforge.net/) (Copyright 2006 Dan-Haim. All rights reserved).
```
>>> import socket
>>> from sockstpy import SockSocket
>>> soc = SockSocket(socket.AF_INET, socket.SOCK_STREAM)
>>> soc.set_server("127.0.0.1", 1080)
>>> soc.connect(("www.google.com", 80))
>>> soc.send("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
36
>>> soc.recv(4096)
'HTTP/1.1 302 Found\r\nCache-Control: private\r\nContent-Type: text/html; charset=UTF-8\r\nReferrer-Policy: no-referrer\r\nLocation: http://www.google.co.il/?gfe_rd=cr&ei=kpAXWcnJEoLb8AffjoGgBQ\r\nContent-Length: 261\r\nDate: Sat, 13 May 2017 23:02:42 GMT\r\n\r\n<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>302 Moved</TITLE></HEAD><BODY>\n<H1>302 Moved</H1>\nThe document has moved\n<A HREF="http://www.google.co.il/?gfe_rd=cr&amp;ei=kpAXWcnJEoLb8AffjoGgBQ">here</A>.\r\n</BODY></HTML>\r\n'
>>> soc.close()
```
All UDP and TCP communication are the same as normal socket except for setting SOCKS server.

SOCKS BIND example:
```
>>> import socket
>>> from sockstpy import SockSocket
>>> soc = SockSocket(socket.AF_INET, socket.SOCK_STREAM)
>>> soc.set_server("127.0.0.1", 1080)
>>> soc.socks_bind("127.0.0.1", 8888)
('127.0.0.1', 50578)
>>> soc.wait_bind_connect()
('127.0.0.1', 8888)
>>> soc.recv(4096)
'test\n'
>>> soc.send("Hello")
5
>>> soc.close()
```

### SockServer
SockSocket inherit from Python's SocketServer (ThreadingTCPServer).
```
>>> from sockstpy import SockServer
>>> server = SockServer(("127.0.0.1", 1080), verbose = True)
>>> server.serve_forever()
14/05/2017 02:21:51 MainThread  : INFO       127.0.0.1:50607 TCP connection granted
14/05/2017 02:21:51 Thread-1    : INFO       127.0.0.1:50607 is Connected.
14/05/2017 02:21:51 Thread-1    : INFO       SOCKS authentication succeeded.
14/05/2017 02:21:51 Thread-1    : INFO       Wait for SOCKS request.
14/05/2017 02:21:51 Thread-1    : INFO       Client is requesting to connect 213.57.24.35:80.
14/05/2017 02:21:54 Thread-1    : INFO       Forward connection established.
14/05/2017 02:22:47 Thread-1    : INFO       213.57.24.35:80 Closed connection.
14/05/2017 02:22:47 Thread-1    : INFO       Closing connection with 127.0.0.1:50607.
```

Reverse connection example:
```
>>> from sockstpy import reverse_server
>>> reverse_server(("127.0.0.1", 1080), ("127.0.0.1", 9999), verbose = True)
14/05/2017 02:31:40 MainThread  : INFO       127.0.0.1:9999 is Connected.
14/05/2017 02:31:40 MainThread  : INFO       SOCKS authentication succeeded.
14/05/2017 02:31:40 MainThread  : INFO       Wait for SOCKS request.
14/05/2017 02:31:40 MainThread  : INFO       Client is requesting to connect 213.57.24.35:80.
14/05/2017 02:31:42 MainThread  : INFO       Forward connection established.
14/05/2017 02:31:54 MainThread  : INFO       213.57.24.35:80 Closed connection.
14/05/2017 02:31:54 MainThread  : INFO       Closing connection with 127.0.0.1:9999.
```

### SocksClient
SocksClient listen to local network address and forwarding all incoming communication from this port to target address through the SOCKS chain:
```
>>> from sockstpy import SocksClient
>>> client = SocksClient(("127.0.0.1", 8888), ("www.google.com", 80), [("127.0.0.1", 1080), ("192.168.1.37", 1080)])
>>> client.connect_socks_chain()
>>> client.tcp_forawrd()
```

### Command-line interface
```
C:\>python -m sockstpy -h
usage: sockstpy [client | server] [-h]

positional arguments:
  [client | server]
    client           Run as SOCKS client
    server           Run as SOCKS server

optional arguments:
  -h, --help         show this help message and exit

C:\>python -m sockstpy server -h
usage: sockstpy server [-h] [-V 4|5] [-U USER] [-P PASS] [-v] [-l LOG]
                       [-r remote_addres] [-f WHITELIST]
                       local_address

positional arguments:
  local_address         local address for forwarding to server

optional arguments:
  -h, --help            show this help message and exit
  -V 4|5                SOCKS versions. default is socks5
  -U USER, --user USER  username for SOCKS authentication if needed
  -P PASS, --pass PASS  username for SOCKS authentication if needed
  -v                    Set verbosity. If log specified written to log file.
  -l LOG                If verbosity is set write to log file.
  -r remote_addres      Reverse connection to SOCKS client
  -f WHITELIST          address of acceptable SOCKS client that allowed to
                        connect. If no address supplied accept every
                        connection. can be more than one address in the format
                        IP:port,IP:port WITHOUT SPACES!!!. Ignored on reverse
                        connection.

C:\>python -m sockstpy client -h
usage: sockstpy client [-h] [-V 4|5] [-U USER] [-P PASS] [-u] [-r port]
                       local_address socks_servers remote_address

positional arguments:
  local_address         local address for forwarding to server
  socks_servers         address of SOCKS server can be morethan one in the
                        format IP:port,IP:port WITHOUT SPACES!!!
  remote_address        target remote address

optional arguments:
  -h, --help            show this help message and exit
  -V 4|5                SOCKS versions. default is socks5
  -U USER, --user USER  username for SOCKS authentication if needed
  -P PASS, --pass PASS  username for SOCKS authentication if needed
  -u, --udp             Use UDP protocol (default is TCP)
  -r port               Wait for reverse connection from SOCKS server to port.
```

## Credits
SockstPy's name and SockstPy's SockSocket module inspired by [PySocks](https://github.com/Anorov/PySocks) (written by @anorov) and by [SocksiPy](http://socksipy.sourceforge.net/) (Copyright 2006 Dan-Haim. All rights reserved).

All the code was written by me.
