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

#### Socks

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
