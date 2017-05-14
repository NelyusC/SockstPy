#-------------------------------------------------------------------------------
# Name:         socksocket.py
# Purpose:      This module provides socket with SOCKS tunnel capabilities.
#
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------

import time
import socket
from __builtin__ import type as saved_type

# Package modules.
from socks import socks
from constants import *
from constants import _ADD_TYPES
from socksexception import SocksException


# Consts.
_BUFSIZE = 8192


class SockSocket(socket.socket):
    """This class implements a subtype of socket that has the ability to
    wrap the underlying OS socket in a SOCKS tunnel and provides the known
    socket functionality over that tunnel."""

    # socket.socket use those as proprty refenced to self._sock need to change
    # this for not showing the socket tunnle parameters but the SockSocket
    # parameters.
    family = None
    type = saved_type
    proto = None

    def __init__(self, family = socket.AF_INET, socktype = socket.SOCK_STREAM,
                 proto = 0, socks_server = None, *args, **kwargs):
        """Initialize socket parameters.

        socks_server = (address, port, version, user, password) or "ipaddress"
        user and password can be None for no authentication."""

        # Protocol check.
        if socktype not in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            err_msg = "SockSocket provide only stream or dtagram communication"
            raise SocksException(err_msg)

        self.family = family
        self.type = socktype
        self.proto = proto

        # Initialize parent socket class. This initialization include the
        # initialization of self._sock the .pyd module of python sockets.
        # We will use self._sock for all comunication with the SOCKS server.
        try:
            socket.socket.__init__(self, family, socktype, proto, *args,
                                   **kwargs)
        except socket.error as e:
            raise SocksException(e.args[1])
        except AttributeError as e:
            raise ValueError("Invalid arguments")
        # The sockets' initializer overrides the delegated methods (such as
        # send() so we need to delete them for providing Socksocket methods.
        for attr in socket._delegate_methods:
            try:
                delattr(self, attr)
            except AttributeError:
                pass

        # Socket for UDP communication after UDP associate and address that
        # the SOCKS server listen to.
        self._udp_sock = None
        self.udp_assoc = None

        # Attribute initialize.
        self.peer_name = None
        self.socks_server = None
        self.socks = None
        self._is_server_connected = None
        if socks_server:
            self.set_server(socks_server)


    def set_server(self, addr, port = DEFAULT_PORT, version = V_SOCKS5,
                   user = None, pwd = None):
        """Set SOCKS server for tunnel.

        addr can be an IP address or Domain name and can be tuple
        with the format (address, port, version, user, password)
        user and password can be None for no authentication. If
        addr is a tuple then all the other parameter is overwritten."""

        # tuple check.
        if isinstance(addr,tuple):
            if len(addr) != 5:
                err = "addr must be tuple with total length of 5 or an address"
                raise SocksException(err)
            addr, port, version, user, pwd = addr

        if self.type == socket.SOCK_DGRAM and version == V_SOCKS4:
            raise SocksException("SOCKS4 can't UDP associate.")

        # Address and parameters check and get _sock.
        self.socks = socks(version)
        s = None
        try:
            if self.socks.get_addr_type(addr):
                addr_info = socket.getaddrinfo(addr, port, socket.AF_UNSPEC,
                                                socket.SOCK_STREAM)
                for res in addr_info:
                    try:
                        s = socket.socket(res[0], socket.SOCK_STREAM, res[2])
                    except socket.error:
                        s = None
        except socket.error as e:
            err = "Invalid server parameters. {0}".format(e.args[1])
            raise SocksException(err)

        if not s:
            raise SocksException("Could not open socket to the SOCKS server")

        # Set the right attributes for connecting through SOCKS server.
        self._sock = s._sock
        self.socks_server = (addr, port, version, user, pwd)
        self._is_server_connected = False


    def remove_server(self):
        """Remove SOCKS server and reset all SOCKS attributes."""

        # Reset SOCKS attributes.
        self.socks_server = None
        self._udp_sock = None
        self.socks = None

        # Change _sock to regular socket.
        self._sock = socket.socket(self.family, self.type, self.proto)._sock


    def _socks_auth(self, user, pwd):
        """User and password authenticaion for connecting the SOCKS server."""

        try:
            self._sock.send(self.socks.client_auth(user, pwd))
            if not self.socks.parse_server_auth(self._sock.recv(_BUFSIZE)):
                raise SocksException("Authentication Failed")
        except socket.error as e:
            raise SocksException("Communication error. {0}".format(e.args[1]))


    def connect_socks_server(self, socks_server):
        """Connecting to SOCKS server."""

        if not isinstance(socks_server, tuple) and len(socks_server) != 5:
            raise SocksException("Server must be tuple with 5 items.")

        addr, port, version, user, pwd = socks_server

        try:
            # If version is SOCKS5 need to negotiate for authentication method.
            if version == V_SOCKS5:
                auth = AUTH_NONE if not user else AUTH_UPASS
                self._sock.send(self.socks.connect_message(auth))
                reply = self._sock.recv(_BUFSIZE)
                auth_rep = self.socks.parse_conn_reply(reply)

                # Check if require authentication.
                if auth_rep == AUTH_UPASS:
                    self._socks_auth(user, pwd)
                elif auth_rep == AUTH_NO_ACCEPTABLE:
                    raise SocksException("No acceptable authentication method")
        except socket.error as e:
            msg = "Unable to connect the SOCKS server. {0}".format(e.args[1])
            raise SocksException(msg)

        self._is_server_connected = True


    def _send_request(self, cmd, addr, port, uid_or_atype):
        """Sends SOCKS request and wait for reply.
        Returns a parsed reply tuple."""

        if not self._is_server_connected:
            try:
                self._sock.connect((self.socks_server[0],self.socks_server[1]))
            except socket.error as e:
                msg = "Unable to connect the SOCKS server. {0}"
                raise SocksException(msg.format(e.args[1]))
            self.connect_socks_server(self.socks_server)

        req = self.socks.generate_request(cmd, addr, port, uid_or_atype)
        try:
            self._sock.send(req)
            reply =self._sock.recv(_BUFSIZE)
            if len(reply) == 0:
                raise SocksException("Server has closed connection")
            reply = self.socks.parse_reply(reply)

            if reply[0] not in (REP_SUCCESS, REP_REQ_GRANT):
                    msg = "The server has rejected the requet. {0}:{1}"
                    raise SocksException(msg.format(reply[1], reply[0]))

        except socket.error as e:
            msg = "Unable to send requst to the SOCKS server. {0}"
            raise SocksException(msg.format(e.args[1]))

        return reply


    def connect(self, addr):
        """Connect the socksocket to remote address.
        The address must be a pair (host, port).

        If socks_server is not defined connect as normal OS socket.
        else connect through the SOCKS server."""

        if self.socks_server:
            # Connect with UDP just bind and set destination address.
            if self.type == socket.SOCK_DGRAM:
                self.peer_name = addr
                return self.bind(("0.0.0.0", 0))
            # Connect to SOCKS server and send CONNECT request.
            address, port = addr
            if self.socks.version == V_SOCKS4:
                uid_or_atype = self.socks_server[3]
            else:
                # Get address type.
                uid_or_atype = self.socks.get_addr_type(address)
                if not uid_or_atype:
                    msg = "The address type is not supported by SOCKS"
                    raise SocksException(msg)

            # Create socket connection.
            self._send_request(CMD_CONNECT, address, port, uid_or_atype)

        # There is no SOCKS server defined. connect as regular socket.
        else:
            socket.socket.connect(self, addr)
        self.peer_name = addr


    def reverse_socks_connect(self, lcl_port = 0, rmt_addr = [], backlog = 0,
                              version = V_SOCKS5, user = None, pwd = None):
        """Listen on lcl_port and try to authenticate with incoming
        connections. rmt_addr is a list of accepted addresses tuple and if
        it is  empty (default) accept every address or port. backlog is like
        the backlog argument in regular socket.listen().
        Returns connected Socksocket."""

        if self.type == socket.SOCK_DGRAM:
            tmp_sock = socket.socket(self.family,socket.SOCK_STREAM,self.proto)
            self._sock = tmp_sock._sock

        self._sock.bind(("", lcl_port))
        self._sock.listen(backlog)

        # Setting socket to non-blocking for solve python bug on Windows that
        # doesn't allow to break if no datagram recieved.
        self._sock.setblocking(False)
        sock = addr = None
        while True:
            try:
                sock, addr = self._sock.accept()
            except socket.error as e:
                time.sleep(1)
            if sock:
                sock.setblocking(True)
                self._sock.setblocking(True)
                break

        if rmt_addr and addr not in rmt_addr:
            sock.close()
            msg = "{0}:{1} tried to connect and refused.".format(*addr)
            raise SocksException(msg)

        # Create new Socksocket.
        socks_serv = (addr[0], addr[1], version, user, pwd)
        socksocket = SockSocket(self.family, self.type, self.proto, socks_serv)
        socksocket._sock = sock
        socksocket.connect_socks_server(socksocket.socks_server)
        if not socksocket._is_server_connected:
            msg ="Failed to authenticate connection by the SOCKS server {}:{}."
            raise SocksException(msg.format(*addr))

        return socksocket


    def bind(self, addr):
        """Implement bind. If using UDP through SOCKS server
        the implementation is for UDP associate operation."""

        if not self.socks_server or self.type != socket.SOCK_DGRAM:
            return self._sock.bind(addr)

        self._udp_sock = socket.socket(self.family, self.type, self.proto)
        return self._udp_sock.bind(addr)


    def socks_bind(self, addr, port):
        """Send SOCKS bind request to the SOCKS server. Returns the new
        SOCKS server bound address and port. The bind request must follow
        another socket connect request for notify the target where to
        connect."""

        if not self.socks_server:
            raise SocksException("SOCKS server is undefined")

        # Set parameters and send request.
        if self. socks.version == V_SOCKS4:
            uid_or_atype = self.socks_server[3]
        else:
            uid_or_atype = self.socks.get_addr_type(addr)

        # Send request and return address and port.
        reply = self._send_request(CMD_BIND, addr, port, uid_or_atype)
        return reply[-2], reply[-1]


    def wait_bind_connect(self):
        """Wait for the second bind reply from SOCKS server and set
        self.peer_name. Return the peer name on success and  raise exception if
        connection is not succeeded."""

        reply = self.socks.parse_reply(self._sock.recv(_BUFSIZE))

        if reply[0] not in (REP_SUCCESS, REP_REQ_GRANT):
                    msg = "The server has rejected the requet. {0}"
                    raise SocksException(msg.format(reply[1]), reply[0])

        self.peer_name = (reply[-2], reply[-1])
        return self.peer_name


    def sendto(self, data, flags_or_addr, addr = None):
        """Send data to unconnected socket. If SOCKS server defined and
        socket type is datagram first connect to SOCKS server and send
        a UDP request. SockSocket doesn't support fragmentation for now."""

        # Use normal sendto if using TCP (if not connected will raise
        # error) or if there is no SOCKS server defined.
        if not self.socks_server or self.type != socket.SOCK_DGRAM:
            if not addr:
                return self._sock.sendto(data, flags_or_addr)
            return self._sock.sendto(data, flags_or_addr, addr)

        if self.socks.version != V_SOCKS5:
            msg = "UDP datagram is not supported by the SOCKS version"
            raise SocksException(msg)

        # Send UDP request for UDP association.
        if not self.udp_assoc:
            if not self._udp_sock:
                self.bind(("", 0))
            dst_addr, dst_port = self._udp_sock.getsockname()
            addr_type = self.socks.get_addr_type(dst_addr)
            reply = self._send_request(CMD_UDP, dst_addr, dst_port, addr_type)
            self.udp_assoc = reply[-2:]

        #Send UDP as standalone with no fragmentation.
        t_addr, t_port = addr if addr else flags_or_addr
        addr_type = self.socks.get_addr_type(t_addr)
        dgram = self.socks.generate_udp(0, t_addr, t_port, addr_type, data)
        if not addr:
            return self._udp_sock.sendto(dgram, self.udp_assoc)
        return self._udp_sock.sendto(dgram, flags_or_addr, self.udp_assoc)


    def send(self, data, flags = 0):
        """Send data through a connected socket. If connected to
        SOCKS server the data will be sent through the server.
        Returns the number of bytes sent."""

        if self.type == socket.SOCK_DGRAM:
            return self.sendto(data, flags, self.getpeername())
        else:
            return self._sock.send(data, flags)


    def sendall(self, data, flags = 0):
        """Send data through a connected socket. If connected to SOCKS server
        the data will be sent through the server. This method continues to
        send data from string until either all data has been sent or an error
        occurs. None is returned on success. On error, an exception is raised,
        and there is no way to determine how much data, if any, was
        successfully sent."""

        if self.type != socket.SOCK_DGRAM or not self.socks_server:
            return self._sock.sendall(data, flags)

        # Need to implement send all with UDP associataion.
        amount = len(data)
        sent = 0
        while sent < amount:
            sent += self.sendto(data[sent:], flags, self.getpeername())
        return None


    def _recv_atrr(self, func, *args, **kwargs):
        """Activate the socket recv method needed."""

        if self.type != socket.SOCK_DGRAM or not self.socks_server:
            recv = getattr(self._sock, func)
        elif not self._udp_sock:
            raise SocksException("Socket must be bound")
        else:
            recv = getattr(self._udp_sock, func)

        return recv(*args, **kwargs)


    def recv(self, bufsize, flags = 0):
        """Recieve data from socket.
        Returns a string representig the data recieved.
        UDP association datagrams need to be parsed."""

        return self._recv_atrr("recv", bufsize, flags)


    def recvfrom(self, bufsize, flags = 0):
        """Receive data from the socket. Returns a pair (string, address)
        where string is a string representing the data received and address
        is the address of the socket sending the data.UDP association
        datagrams need to be parsed."""

        return self._recv_atrr("recvfrom", bufsize, flags)


    def recvfrom_into(self, buffer, nbytes = None, flags = 0):
        """Receive data from the socket, writing it into buffer instead of
        creating a new string. Returns a pair (nbytes, address) where nbytes is
        the number of bytes received and address is the address of the socket
        sending the data. UDP association datagrams need to be parsed."""

        return self._recv_atrr("recvfrom_into", buffer, nbytes, flags)


    def recv_into(self, buffer, nbytes = None, flags = 0):
        """Receive up to nbytes bytes from the socket, storing the data into
        a buffer rather than creating a new string. Returns the number of bytes
        received. UDP association datagrams need to be parsed."""

        return self._recv_atrr("recv_into", buffer, nbytes, flags)


    def recv_udp(self, bufsize, flags = 0):
        """Use recv and parse data recieved as in UDP associate.
        Returns the parsed data."""

        return self.socks.parse_udp(self.recv(bufsize, flags))[-1]


    def recvfrom_udp(self, bufsize, flags = 0):
        """Use recvfrom and parse data recieved as in UDP associate.
        Returns value is a pair (string, address) where string is the
        parsed data."""

        string, address = self.recvfrom(bufsize, flags)
        addr, port , data = self.socks.parse_udp(string)[-3:]
        return data, (addr, port)


    def is_socks_conn(self):
        """Preform recv to the connection from SOCKS server (ignore the data
        received). Relevant only for UDP SockSocket when setting SOCKS server.
        If closed return True else False. If not connected to SOCKS server may
        raise socket.error."""

        return len(self._sock.recv(_BUFSIZE)) == 0


    def get_udp_sock(self):
        """Returns the UDP socket from UDP association. Don't use this socket
        for communication operations outside the SockSocket. Use this for
        select operation. If server not configured or socket type is not udp
        returns None."""

        return self._udp_sock


    def getpeername(self):
        """Return the remote address to which the socket is connected."""

        if not self.socks_server:
            return self._sock.getpeername()
        return self.peer_name


    def settimeout(self, value):
        """Set a timeout on blocking socket operations. The value argument
        can be a nonnegative float expressing seconds, or None.
        If a float is given, subsequent socket operations will raise a timeout
        exception if the timeout period value has elapsed before the operation
        has completed. Setting a timeout of None disables timeouts on socket
        operations."""

        self._sock.settimeout(value)
        if self._udp_sock:
            self._udp_sock.settimeout(value)


    def gettimeout(self):
        """Return the timeout in seconds (float) associated with socket
        operations, or None if no timeout is set."""

        return self._sock.gettimeout()


    def setblocking(self, flag):
        """Set blocking or non-blocking mode of the socket. if flag is 0,
        the socket is set to non-blocking, else to blocking mode."""

        if flag:
            self.settimeout(None)
        else:
            self.settimeout(0.0)


    def dup(self):
        """Return a new socket object connected to the same system resources
        including SOCKS server and Socksocket parameters."""

        socksocket = SockSocket(self.family, self.type,
                                self.proto, self.socks_server)
        socksocket._sock = self._sock
        socksocket.peer_name = self.peer_name
        socksocket._udp_sock = self._udp_sock
        socksocket.udp_assoc = self.udp_assoc
        socksocket._is_server_connected = self._is_server_connected
        return socksocket


    def close(self):
        """Close the socket.  All future operations on the socket
        object will fail."""

        self._sock.close()
        if self._udp_sock:
            self._udp_sock.close()

