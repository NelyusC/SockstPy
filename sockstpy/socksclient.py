#-------------------------------------------------------------------------------
# Name:         socksclient.py
# Purpose:      A basic SOCKS client for traffic forwarding through SOCKS
#               tunnel.
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------

import time
import socket
import threading


# Package modules.
import socksocket
from constants import *
from constants import _VERSIONS
from _forwarder import Forwarder
from socksocket import SockSocket
from socksexception import SocksException


#Consts
_BUFSIZE = 8192


class SocksClient(object):
    """A basic SOCKS client that provide traffic forwarding through SOCKS
    tunnle. SocksClient only support TCP forwarding using connect request
    or single udp communication (without multiple senders).
    For more advanced SOCKS operation use SockSocket."""


    def __init__(self, local_address, remote_addres, socks_chain = [],
                 udp = False, version = V_SOCKS5, user = None, pwd = None):
        """Initialize SocksClient properties.

        local_address is where the client listen and from there forward the
        traffic to tunnle and remote_address is to where sending the traffic
        after forwarded in the tunnle (Both in (address, port) format).
        socks_chain is a list of SOCKS server addresses and each server should
        be in those format:

            "127.0.0.1' (or any other IP address)
            (ip address, port)
            (ip address, port, version, user, pwd)

        If data omitted it will replace by the default values specified
        in the initializing function (default port is 1080 as specified in
        the SOCKS RFC). for example:

("127.0.0.1", 8888) -> ("127.0.0.1", 8888, self.version, ,self.user, self.pwd)
"127.0.0.1" -> ("127.0.0.1", 1080, self.version, ,self.user, self.pwd)
("127.0.0.1", 8888, 5, "user", "pwd")->("127.0.0.1", 8888, 5, ,"user","pwd")

        Any other option will cause an errors."""

        # Version check.
        if version not in _VERSIONS:
            raise ValueError("Invalid SOCKS version")

        self.remote_addres = remote_addres
        self.local_address = local_address
        self.version = version
        self.user = user
        self.pwd = pwd
        self.udp = udp
        self.connected = False
        self.key_event = threading.Event()
        self._in_sock = None
        self._socksock= None
        self._forwarder = None

        # Set socks_chain as property.
        self.socks_chain = socks_chain

        self._set_sockets()


    def _get_chain(self):
        """Returns the SOCKS chain for setting socks_chain as a property."""

        return self._socks_chain


    def _set_chain(self, chain):
        """Set the SOCKS chain for for setting socks_chain as a property."""

        if self.connected:
            msg = "Can't change SOCKS chain after connect through it"
            raise SocksException(msg)

        if not isinstance(chain, list):
            raise SocksException("socks_chain must be a list")

        if self.udp and len(chain) != 1:
            msg = "SocksClient support only one chain link for UDP"
            raise SocksException(msg)

        # Check if every item in the chain is string or tuple
        # with the length of 2 or 5.
        for i in chain:
            if (not isinstance(i[0], str) and
                    (not isinstance(i, tuple) or (len(i) not in (2, 5)))):
                 raise SocksException("Invalid items is sock_chain")

        self._socks_chain = chain


    # Set self.sock_chain to a propery.
    socks_chain = property(_get_chain, _set_chain, "SOCKS servers chain")


    def remove_server(self, server):
        """Removes server from the socks_chain."""

        if server in self.socks_chain:
            self.socks_chain = self.socks_chain.remove(server)


    def add_server(self, server):
        """Adds server to socks_chain."""

        self.socks_chain = self.socks_chain.append(server)


    def _get_server_from_chain(self, server):
        """returns a server tuple with 5 items."""

        # Server is tuple with 5 items.
        if (isinstance(server, tuple) and
                len(self.socks_chain[0]) == 5):
            addr, port, version, user, pwd = server

        # Server is tuple with 2 items.
        elif (isinstance(self.socks_chain[0], tuple) and
                len(self.socks_chain[0]) == 2):
            addr, port = self.socks_chain[0]
            version, user, pwd = self.version, self.user, self.pwd

        # Server is string
        else:
            addr, port = server, DEFAULT_PORT
            version, user, pwd = self.version, self.user, self.pwd

        return addr, port, version, user, pwd


    def connect_socks_chain(self):
        """Connect the SOCKS server and request to connecet the remote address
        specified in remote_address."""

        if not self.socks_chain:
            return

        # Set the first SOCKS server in the chain.
        if not self._socksock.socks_server:
            server = self._get_server_from_chain(self.socks_chain[0])
            self._socksock.set_server(server)

        # Connect all SOCKS server in chain.
        for i in self.socks_chain[1:]:
            server = self._get_server_from_chain(i)
            self._socksock.connect(server[:2])
            self._socksock.connect_socks_server(server)

        self.connected = True


    def reverse_connect(self, lcl_port = DEFAULT_REVERSE_PORT, backlog = 0):
        """Wait for a connection from the first server in socks_chain and
        reverse connect him. If there is no servers in socks_chain wait for any
        connection and add it to socks_chain."""

        # Create a new SockSocket for listening.
        l_sock = SockSocket(self._socksock.family, self._socksock.type,
                            self._socksock.proto, self._socksock.socks_server)

        # Set reverse connection parameters.
        if self.socks_chain:
            server = self._get_server_from_chain(self.socks_chain[0])
            addr, port, version, user, pwd = server
            rmt_addr = [(addr, port)]
        else:
            version, user, pwd = self.version, self.user, self.pwd
            rmt_addr = []

        # Receive connection.
        acc_socksock = l_sock.reverse_socks_connect(lcl_port, rmt_addr,backlog,
                                                    version, user, pwd)
        if acc_socksock:
            self._socksock = acc_socksock
            self._forwarder = Forwarder(self.local_address, self._socksock,
                                        self.key_event, self.version)
            self.connect_socks_chain()

        # If succedded there is no need to listen and connected will be True.
        l_sock.close()
        return self.connected


    def tcp_forawrd(self):
        """Wait for incoming tcp connection to local_address and start
        forwarding traffic through connected SOCKS chain (need to preform
        connect_socks_chain or reverse_connect)."""

        # Start listen and connect the remote address.
        self._in_sock.bind(self.local_address)
        self._in_sock.listen(5)
        self._in_sock.setblocking(False)
        self._socksock.connect(self.remote_addres)

        try:
            forward_threads = []
            while True:
                # Accept connections and set arguments for forwarder thread.
                connection = addr = None
                try:
                    connection, addr = self._in_sock.accept()
                except socket.error as e:
                    pass

                if not connection:
                    # Check if SockSocket connected to server is alive.
                    if forward_threads:
                        if True not in [i.isAlive() for i in forward_threads]:
                            try:
                                if len(self._socksock.recv(_BUFSIZE)) == 0:
                                    break
                            except socket.error as e:
                                break
                    time.sleep(1)
                    continue

                # Run forwarder thread.
                forward_data = {self._socksock:"", connection:""}
                args_tuple = (forward_data, self._forwarder.tcp_receive,
                              self._forwarder.tcp_send)
                forward_handler=threading.Thread(target=self._forwarder.forward,
                                                 args = args_tuple)
                forward_handler.daemon = True
                forward_threads.append(forward_handler)
                forward_handler.start()

        except KeyboardInterrupt:
            self.key_event.set()
        finally:
            self.close_sockets()
            self._set_sockets()


    def udp_forward(self):
        """Wait for incomming datagram and start forwarding datagrams between
        the sender and the remote address(need to preform connect_socks_chain
        or reverse_connect)."""

        # Getting the first datagram for connecting all sockets.
        self._in_sock.bind(self.local_address)
        self._socksock.connect(self.remote_addres)
        # Setting socket to non-blocking for solve python bug on Windows that
        # doesn't allow to break if no datagram recieved.
        dgram = addr = None
        while not dgram:
            self._in_sock.settimeout(1)
            try:
                dgram, addr = self._in_sock.recvfrom(_BUFSIZE)
            except socket.error as e:
                time.sleep(1)

        self._socksock.send(dgram)
        self._in_sock.connect(addr)

        # Setting forward_data for forward and forward.
        forward_data = {self._socksock.get_udp_sock():[], self._in_sock:[],
                        self._socksock:[]}
        self._forwarder.forward(forward_data, self._forwarder.udp_client_recv,
                                self._forwarder.udp_client_send)
        self.close_sockets()
        self._set_sockets()


    def close_sockets(self):
        """Close incoming and outgoing sockets."""

        if self._in_sock:
            self._in_sock.close()
        if self._socksock:
            self._socksock.close()


    def _set_sockets(self):
        """Set the incomming and outgoing sockets."""

        socktype = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM

        # Check remote address family and set SockSocket.
        family = socket.getaddrinfo(*self.local_address)[0][0]
        self._socksock = SockSocket(family, socktype)

        # Check remote address family and set incomming traffic socket.
        family = socket.getaddrinfo(*self.local_address)[0][0]
        self._in_sock = socket.socket(family, socktype)

        # Modify forwarder as needed.
        self._forwarder = Forwarder(self.local_address, self._socksock,
                                    self.key_event, self.version)
        self.connected = False
