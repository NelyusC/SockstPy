#-------------------------------------------------------------------------------
# Name:         _forwarder.py
# Purpose:      This module provide socket forward functions for SOCKS
#               tunneling.
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------

import time
import socket
import select
import logging

# Package modules.
from socks import socks
from constants import *
from constants import _VERSIONS
from socksocket import SockSocket
from socksexception import SocksException

# Consts.
_BUFSIZE = 8192
_NO_LOG = 100


class Forwarder(object):
    """Handle all forwarding operations for SOCKS server and client."""

    def __init__(self, server_addr, sock, event, version = V_SOCKS5,
                 logger = None):
        """Initialize instance variables.
        sock must be a connected TCP socket (if SOCKS server use Forwarder sock
        need to be TCP socket connected to the SOCKS client). If a SocksClient
        object use Forwarder the sock need to be the SockSocket.
        version is theSOCKS version.
        logger must be a configured logging.Logger object or None"""

        if ((logger and not isinstance(logger, logging.Logger)) or
                not isinstance(sock, socket.socket) or
                version not in _VERSIONS):
            # If one parameter is not the right type raise ValueError.
            raise ValueError("Recieved invalid argument.")

        # if logger is None set a dummy logger.
        if not logger:
            logger = logging.getLogger("Dummy")
            logger.setLevel(_NO_LOG)

        self.server_addres = server_addr
        self.sock = sock
        self.socks = socks(version)
        self.logger = logger
        self.event = event
        self.udp_relay = None


    def open_socket(self, addr, port, addr_type, socktype):
        """Open a new socket and bind it. If need to open a socket for
        connect() should use sock.create_connection(). Returns a socket
        or None if couldn't open one."""

        if addr_type != self.socks.get_addr_type(self.server_addres[0]):
            return None

        new_sock = None
        try:
            addr_list = socket.getaddrinfo(addr, port, socket.AF_UNSPEC,
                                           socktype, 0, socket.AI_PASSIVE)
        except socket.error as e:
            self.logger.warning("getaddrinfo error.{}".format(e.args[1]))
            addr_list = []

        # Try to open socket if getaddrinfo succeeded.
        for res in addr_list:
            family, socktype, proto, canonname, addr = res
            try:
                # Try bind after getting address.
                new_sock = socket.socket(family, socktype, proto)
                new_sock.bind((self.server_addres[0], 0))
            except socket.error as e:
                if new_sock:
                    new_sock.close()
                new_sock = None
                continue
            break

        return new_sock


    def accept_connection(self,  wait_sock):
        """Set the socket for listening and accept connection. Return connected
        socket on success and None if failure occurred."""

        connection = None
        try:
            wait_sock.listen(1)
            connection, addr = wait_sock.accept()
        except socket.error as e:
            log_msg = "Error while trying accept connection.{}"
            self.logger.warning(log_msg.format(e.args[1]))

        return connection


    def _select_ready(self, inputs, outputs):
        """Get a lists for sockets and returns a lists for sockets that
        ready for sending or receiving data and boolean value if loop
        termination needed or not."""

        terminate = False
        in_ready = out_ready = []
        while True:
            try:
                in_ready, out_ready, err_ready = select.select(inputs, outputs, [], 0.1)
                if self.event.is_set():
                    terminate = True
                    break
                if in_ready or out_ready:
                    break
            except select.error as e:
                terminate = True
                log_msg = "Select error while forwarding. {}"
                self.logger.warning(log_msg.format(e.args[1]))
                break

        return in_ready, out_ready, terminate


    def forward(self, forward_data, receive_func, send_func):
        """Factory function that manage all forwrding operaions between
        connected sockets. forward_data must be a dictionary with sockets as
        keys and data to send as value (the form of the data is different
        between forwarding functions the user must verify suitability).
        receive_func and send_func are function the the function use for
        forwarding.
        All receive_func and send_func must receive self, a list of connected
        socket and forward_data dictionary.
        All receive_func and send_func must must return a boolean."""

        # Set all socket to non-blocking.
        for sock in forward_data.keys():
            sock.setblocking(0)

        terminate = False
        while not terminate:

            inputs = forward_data.keys()
            # Add sockets to output if there is data to send.
            outputs = []
            outputs.extend(k for k,v in forward_data.items() if len(v) > 0)
            # Check who can receive and send data.
            in_ready, out_ready, term_sel = self._select_ready(inputs, outputs)

            terminate_receive = receive_func(in_ready, forward_data)
            terminate_send = send_func(out_ready, forward_data)
            terminate = terminate_send or terminate_receive or term_sel

            # If KeyboardInterrupt sent terminate.
            if self.event.is_set():
                terminate = True


    def tcp_receive(self, in_ready, forward_data):
        """Receive data from sockets and put it in the other sockets
        forward data.
        forwrd_data is in the form of {socket1:"data", socket2:"data"}"""

        terminate = False
        first, second = forward_data.keys()

        for inr in in_ready:
            other = first if inr == second else second

            # Receive data from socket.
            data = None
            try:
                data = inr.recv(_BUFSIZE)
            except socket.error as e:
                terminate = True
                log_msg = "Error while forwarding. {}"
                self.logger.warning(log_msg.format(e.args[1]))

            # Check data and forward to the other socket.
            if data is not None:
                if len(data) > 0:
                    forward_data[other] += data
                else:
                    terminate = True
                    log_msg = "{}:{} Closed connection."
                    self.logger.info(log_msg.format(*inr.getpeername()))

            return terminate


    def tcp_send(self, out_ready, forward_data):
        """Send data received from the other socket.
        forwrd_data is in the form of {socket1:"data", socket2:"data"}"""

        terminate = False
        written = 0

        # Send data.
        for outr in out_ready:
            try:
                written = outr.send(forward_data[outr])
            except socket.error as e:
                terminate = True
                log_msg = "Error while forwarding. {}".format(e.args[1])
                self.logger.warning(log_msg)

            # Delete the data that already sent.
            if written > 0:
                forward_data[outr] = forward_data[outr][written:]

        return terminate


    def _udp_relay_req(self, relay_dgram, forward_data):
        """Parse the relay datagram and find a socket that can send the data.
        modify forward_data as needed.
        forwrd_data is in the form of:
        {self.sock:[], socket1:["datagram1", "datagram2"], socket2:["datagram3"]}"""

        # relay_dgram
        parsed = self.socks.parse_udp(relay_dgram)
        addr_type, addr, port, data = parsed[1:]

        # Check if there is connected socket with the target.
        found = False
        for sock in forward_data.keys():
            if (sock.getpeername() == (addr, port) and
                    sock.family == socket.SOCK_DGRAM):
                forward_data[sock].append(data)
                found = True

        # Open new socket if needed.
        if not found:
            new_sock = self.open_socket(addr, port, addr_type,
                                        socket.SOCK_DGRAM)
            if new_sock:
                try:
                    new_sock.connect((addr, port))
                    new_sock.setblocking(0)
                    forward_data[new_sock] = [data]
                except socket.error:
                    # If couldn't open socket drop the data silently as
                    # specified in the RFC1928.
                    new_sock.close()


    def udp_assoc_recv(self, in_ready, forward_data):
        """Receive data from sockets and put it in the other relay side sockets
        forward data.
        forwrd_data is in the form of:
        {self.sock:[], socket1:["datagram1", "datagram2"], socket2:["datagram3"]}"""

        terminate = False

        try:
            for inr in in_ready:
                # The UDP association continue until the TCP connection is
                # closed. If received 0 than closed.
                if inr == self.sock and len(self.sock.recv(_BUFSIZE)) == 0:
                    terminate = True

                # If received from client need to parse header first.
                elif inr == self.udp_relay:
                    self._udp_relay_req(inr.recv(_BUFSIZE), forward_data)

                #
                else:
                    addr, port = inr.getpeername()
                    addr_type = self.socks.get_addr_type(addr)
                    dgram = self.socks.generate_udp(0, addr, port, addr_type,
                                                    inr.recv(_BUFSIZE))
                    forward_data[self.udp_relay].append(dgram)
        except (socket.error, SocksException) as e:
            # If error occurred when trying to recieve data drop datagram as
            # specified in the RFC1928.
            pass

        return terminate


    def udp_send(self, out_ready, forward_data):
        """Send all datagrams received from the other socket.
        forwrd_data is in the form of:
            {socket1:["datagram1", "datagram2"], socket2:["datagram3"]}"""

        # Send data.
        for outr in out_ready:
            for i in range(len(forward_data[outr])):
                try:
                    outr.send(forward_data[outr].pop(i))
                except socket.error as e:
                    # If error occurred when trying to send datagram
                    #drop it as specified in the RFC1928.
                    pass

        return False


    def udp_client_recv(self, in_ready, forward_data):
        """Receive data from sockets and put it in the other relay side sockets
        forward data. if using SockSocket use recv_udp.
        forwrd_data is in the form of:
        {self.sock:[], socket1:["datagram1", "datagram2"], socket2:["datagram3"]}"""

        # Find regular socket.
        regular = None
        udp_sock = self.sock.get_udp_sock()
        for i in forward_data.keys():
            if i not in (self.sock, udp_sock):
                regular = i

        terminate = False
        for inr in in_ready:

            dgram = None
            try:
                # If SockSocket receives "" than SOCKS server disconnected and
                # need to stop forwrding.
                if inr == self.sock and inr.is_socks_conn():
                    terminate = True

                # Check if inr is SockSocket._udp_sock and receive.
                elif inr == udp_sock:
                    dgram = self.sock.recv_udp(_BUFSIZE)
                    forward_data[regular].append(dgram)

                # Regular socket. Receive and put in SockSocket datagrams.
                else:
                    dgram = inr.recv(_BUFSIZE)
                    forward_data[self.sock].append(dgram)
                    forward_data[udp_sock].append(dgram)
            except (socket.error, SocksException) as e:
                # If error occurred when trying to send datagram drop it
                # as normal failling datagram.
                pass

        return terminate


    def udp_client_send(self, out_ready, forward_data):
        """Send all datagrams received from the other socket.
        forwrd_data is in the form of:
        {self.sock:[], socket1:["datagram1", "datagram2"], socket2:["datagram3"]}"""

        udp_sock = self.sock.get_udp_sock()

        # Send with SockSocket send only.
        if self.sock._udp_sock in out_ready:
            out_ready.remove(self.sock.udp_sock)
            if self.sock not in out_ready:
                out_ready.append(self.sock)
            forward_data[self.sock.udp_sock] = []

        return self.udp_send(out_ready, forward_data)


    def udp_associate(self, udp_relay, addr, port):
        """Start SOCKS5 UDP associate until the main TCP connection is dead.
        udp_relay is the UDP socket from the client. addr and port are those
        the SOCKS client send in his request."""

        self.udp_relay = udp_relay
        # Connect socket to the address for better forwarding managment.
        dgram = None
        if (addr in ('0000:0000:0000:0000:0000:0000:0000:0000', "0.0.0.0") or
                port == 0):
            inputs = [self.udp_relay,self.sock]
            in_ready, out_ready, terminate = self._select_ready(inputs, [])

            # The client closed TCP connection.
            if self.sock in in_ready and len(self.sock.recv(_BUFSIZE)) == 0:
                return

            # Connect after received the first datagram.
            if self.udp_relay in in_ready:
                dgram, (addr, port) = self.udp_relay.recvfrom(_BUFSIZE)

        # The client supplied address and port or already send datagem.
        self.udp_relay.connect((addr, port))

        # Add the client TCP connection for closing association when needed.
        forward_data = {self.sock:[], self.udp_relay:[]}
        if dgram:
            self._udp_relay_req(dgram, forward_data)
        self.forward(forward_data, self.udp_assoc_recv, self.udp_send)

        # Close all sockets when done.
        for sock in forward_data.keys():
            sock.close()

