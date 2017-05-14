#-------------------------------------------------------------------------------
# Name:         sockserver.py
# Purpose:      This module provides a SOCKS server with SOCKS4 and SOCKS5
#               capabilities.
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------

import socket
import logging
import threading
from SocketServer import ThreadingTCPServer, BaseRequestHandler

# Package modules.
from socks import socks
from constants import *
from constants import _VERSIONS
from _forwarder import Forwarder
from socksexception import SocksException


# Consts.
_BUFSIZE = 8192
_LOG_FORMAT = "%(asctime)s %(threadName)-12s: %(levelname)-10s %(message)s"
_TIME_FORMAT = "%d/%m/%Y %H:%M:%S"
_NO_LOG = 100


class SocksManager(object):
    """Manage all SOCKS opertaion requested by the SOCKS client after TCP
    connection established."""

    def __init__(self, server_address, logger, connection, event,
                 version = V_SOCKS5, user = None, pwd = None):
        """Initialize SocksManager properties.
        logger must to be a configured logging.Logger object. connection
        must be a TCP socket connected to a SOCKS client. version is the
        SOCKS version and user and password is the authentication details
        if needed."""

        # Parameter check.
        if (not isinstance(connection, socket.socket) or
                not isinstance(logger, logging.Logger) or
                (user and not isinstance(user, str)) or
                version not in _VERSIONS or
                (pwd and not isinstance(pwd, str))):
            # If one parameter is not the right type raise ValueError.
            raise ValueError("Recieved invalid argument.")

        self.sock = connection
        self.socks = socks(version)
        self.user = user
        self.pwd = pwd
        self.logger = logger
        self.server_address = server_address
        self.forwarder = Forwarder(server_address, connection, event, version,
                                   logger)
        self.peer_name = connection.getpeername()


    def close_socket(self):
        """Close the socket connected to the client."""

        addr, port = self.peer_name
        self.logger.info("Closing connection with {}:{}.".format(addr, port))
        self.sock.close()


    def _upass_auth(self):
        """User and password authentication method."""

        self.logger.info("Wait for user and password.")
        user, pwd = self.socks.parse_auth(self.sock.recv(_BUFSIZE))

        if (self.user, self.pwd) == (user, pwd):
            self.sock.send(self.socks.auth_status(REP_SUCCESS))
            self.logger.info("Client used correct user and password.")
            return True

        self.sock.send(self.socks.auth_status(REP_GENERAL_FAILURE))
        self.logger.warning("Client used incorrect user and password.")
        return False


    def socks_authenticate(self):
        """Wait for SOCKS connection and authentication. If the authentication
        process succeeded return True and else False."""

        addr, port = self.sock.getpeername()
        self.logger.info("{}:{} is Connected.".format(addr, port))

        # SOCKS4 doesn't support client authentication.
        if self.socks.version == V_SOCKS4:
            self.logger.info("SOCKS authentication succeeded.")
            return True

        # Parse client connect and choose authentication method
        methods = self.socks.parse_connect(self.sock.recv(_BUFSIZE))
        if not self.user:
            self.sock.send(self.socks.connect_reply(AUTH_NONE))
            self.logger.info("SOCKS authentication succeeded.")
            return True

        elif AUTH_UPASS in methods:
            self.sock.send(self.socks.connect_reply(AUTH_UPASS))
            return self._upass_auth()

        # Client didn't provide acceptable authentication method.
        self.sock.send(self.socks.connect_reply(AUTH_NO_ACCEPTABLE))
        log_msg = "Client using unacceptable authentication methods."
        self.logger.warning(log_msg)
        return False


    def _reply_version(self, reply_v5, reply_v4):
        """Return reply_v5 if SOCKS version is 5 and reply_v4 if the SOCKS
        version is 4."""

        if self.socks.version == V_SOCKS5:
            return reply_v5

        return reply_v4


    def _reply_version_err(self, reply_v5, reply_v4, addr = None, port = None):
        """Send error reply by version and close connection with the client."""

        rep = self._reply_version(reply_v5, reply_v4)
        if not addr or not port:
            self._send_reply(rep)
        else:
            self._send_reply(rep, addr, port)


    def _send_reply(self, rep, addr = "0.0.0.0", port = 0):
        """Send reply for SOCKS client request. Default address and port are
        for failure replies"""

        if self.socks.version == V_SOCKS5:
            params = (rep, addr, port, self.socks.get_addr_type(addr))
        else:
            params = (rep, addr, port)

        self.sock.send(self.socks.generate_reply(*params))


    def connect_request(self, addr, port):
        """Preform SOCKS connect after received request from the client."""

        log_msg = "Client is requesting to connect {}:{}.".format(addr, port)
        self.logger.info(log_msg)

        # Trying to connect target.
        try:
            forward_socket = socket.create_connection((addr, port))
        except socket.error as e:
            log_msg = "Could not connect the target. {}".format(e.args[1])
            self.logger.warning(log_msg)
            return self._reply_version_err(REP_GENERAL_FAILURE, REP_REQ_REJECT)

        # Send connect reply.
        self.logger.info("Forward connection established.")
        bnd_addr, bnd_port = forward_socket.getsockname()
        rep = self._reply_version(REP_SUCCESS, REP_REQ_GRANT)
        self._send_reply(rep, bnd_addr, bnd_port)

        # Start forwarding and close sockets when finished.
        forward_data = {self.sock:"", forward_socket:""}
        self.forwarder.forward(forward_data, self.forwarder.tcp_receive,
                               self.forwarder.tcp_send)
        forward_socket.close()


    def _set_sock_listen(self, addr, port, addr_t, socktype):
        """Sets socket for listening for bind and UDP associate requests.
        Returns the socket ready for listening and None if couldn't."""

        listen_sock = self.forwarder.open_socket(addr, port, addr_t, socktype)
        if not listen_sock:
            self.logger.warning("Could not open socket for listening.")
            return self._reply_version_err(REP_GENERAL_FAILURE, REP_REQ_REJECT)

        # Open socket succeeded. Reply details to client.
        l_addr, l_port = listen_sock.getsockname()[:2]
        self.logger.info("Socket is listening on {}:{}".format(l_addr, l_port))
        rep = self._reply_version(REP_SUCCESS, REP_REQ_GRANT)
        self._send_reply(rep, l_addr, l_port)
        return listen_sock


    def _wait_accept(self, wait_sock, addr, port):
        """Wait for incoming connection. Return connected socket on success
        and None if failure occurred."""

        # Try to accept connection.
        target_connection = self.forwarder.accept_connection(wait_sock)
        if not target_connection:
            return self._reply_version_err(REP_GENERAL_FAILURE, REP_REQ_REJECT)

        # Check if connection details is the same as reauested by the client.
        t_addr, t_port = target_connection.getpeername()[:2]
        if (addr, port) != (t_addr, t_port):
            log_msg = "Accepted unrecognized connection. {}:{}"
            self.logger.warning(log_msg.format(t_addr, t_port))
            target_connection.close()
            rep = (REP_CON_UNALLOWED, REP_REQ_REJECT, t_addr, t_port)
            return self._reply_version_err(*rep)

        # Accept connection. Reply success to the client.
        log_msg = "Accepted connection {}:{}.".format(t_addr, t_port)
        self.logger.info(log_msg)
        rep = self._reply_version(REP_SUCCESS, REP_REQ_GRANT)
        self._send_reply(rep, t_addr, t_port)
        return target_connection


    def bind_request(self, dst_addr, dst_port, addr_type):
        """Preform SOCKS connect after received request from the client."""

        log_msg = "Client is requesting to bind for {}:{}."
        self.logger.info(log_msg.format(dst_addr, dst_port))

        # Set socket for listening.
        bind_socket = self._set_sock_listen(dst_addr, dst_port, addr_type,
                                            socket.SOCK_STREAM)
        if not bind_socket:
            return

        # Open socket succeeded. Wait for incoming connection.
        bind_conn = self._wait_accept(bind_socket, dst_addr, dst_port)
        if not bind_conn:
            bind_socket.close()
            return
        # Accepted connection. start forwarding and close all socket when done.
        else:
            forward_data = {bind_conn:"", self.sock:""}
            self.forwarder.forward(forward_data, self.forwarder.tcp_receive,
                                   self.forwarder.tcp_send)
            bind_conn.close()
            bind_socket.close()


    def udp_request(self, addr, port, addr_type):
        """Set UDP associate for SOCKS client request.
        SocksManager doesn't support fragmentation for now."""

        log_msg = "Client is requesting for UDP associate with {}:{}."
        self.logger.info(log_msg.format(addr, port))

        # Set socket for UDP association.
        udp_relay = self._set_sock_listen(addr, port, addr_type,
                                          socket.SOCK_DGRAM)
        if not udp_relay:
            return

        self.forwarder.udp_associate(udp_relay, addr, port)

        # Socket cleanup.
        udp_relay.close()


    def _verify_userid(self, userid):
        """Verify userid if userid configured as self.user."""

        if self.user:
            return userid == self.user
        return True


    def verify_request(self, request):
        """Verify received request and return request parameters."""

        # Parse by SOCKS version.
        if self.socks.version == V_SOCKS5:
            cmd, addr_type, dst_addr, dst_port = request
        else:
            addr_type = ADD_IPV4
            cmd, dst_addr, dst_port, userid = request
            # for SOCKS4 need to check user ID.
            if not self._verify_userid(userid):
                logger.warning("Client send a request with wrong userid.")
                self._send_reply(REP_DIFF_USERID)
                return

        # Check all other parameters.
        if not self.socks.validate_msg_params(addr_type, dst_addr, dst_port):
            logger.warning("Client send a request with wrong parameters.")
            self._reply_version_err(REP_GENERAL_FAILURE, REP_REQ_REJECT)

        return cmd, dst_addr, dst_port, addr_type


    def get_request(self):
        """Get request from the SOCKS client and act accordingly."""

        self.logger.info("Wait for SOCKS request.")
        request = self.socks.parse_request(self.sock.recv(_BUFSIZE))
        cmd, dst_addr, dst_port, addr_type = self.verify_request(request)

        # Check cmd type.
        if cmd == CMD_CONNECT:
            self.connect_request(dst_addr, dst_port)
        elif cmd == CMD_BIND:
            self.bind_request(dst_addr, dst_port, addr_type)
        elif cmd == CMD_UDP and self.socks.version == V_SOCKS5:
            self.udp_request(dst_addr, dst_port, addr_type)
        else:
            self.logger.warning("Client requested unsupported action.")
            self._reply_version_err(REP_CMD_NOT_SUPPORT, REP_REQ_REJECT)


class SocksHandler(BaseRequestHandler):
    """Handle all TCP connection and initiate SOCKS server operation."""

    def setup(self):
        """Set SocksManager."""

        self.manager = SocksManager(self.server.server_address,
                                    self.server.logger, self.request,
                                    self.server.key_event, self.server.version,
                                    self.server.user, self.server.pwd)


    def handle(self):
        """Using SocksManager for SOCKS authentication and SOCKS requests."""

        _handle_socksmanager(self.manager)


    def finish(self):
        """Close connection when finish handle SOCKS client."""

        self.manager.close_socket()


class SockServer(ThreadingTCPServer):
    """SOCKS server that handle all SOCKS clients' requests."""


    def __init__(self, server_address, RequestHandlerClass = SocksHandler,
                 version = V_SOCKS5, rmt_addr = [], user = None, pwd = None,
                 verbose = False, log = None, log_fmt = None, time_fmt = None):
        """Create ThreadingTCPServer with SOCKS parameters. user and pwd are
        optional for require client authentication and tmt_addr is a list of
        address stractures the server should accept. if rmt_addr empty accept
        every request and if the port is 0 accept every port. If verbose True
        write log messages to screen or to a log file if supplied a log
        argument. log_fmt and time_fmt are the log messages format (if None
        use the default format)."""

        # Verify RequsetHandlerClass can handle SOCKS.
        if not issubclass(RequestHandlerClass, SocksHandler):
            msg = "{} is not a Sockshandler class"
            raise ValueError(msg.format(RequestHandlerClass.__name__))
        if ((user and not isinstance(user, str)) or
                (pwd and not isinstance(pwd, str)) or
                not isinstance(rmt_addr, list) or
                version not in _VERSIONS):
            raise ValueError("Invalid arguments.")

        ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass)

        # Add SOCKS instance variables.
        self.version = version
        self.rmt_addr = rmt_addr
        self.user = user
        self.pwd = pwd
        self.key_event = threading.Event()

        # set logging.
        self.logger = _set_logger(verbose, log, log_fmt, time_fmt)


    def verify_request(self, request, client_address):
        """Return True if the client_address is in rmt_addr."""

        if self.rmt_addr:
            # Check rmt_list list
            if client_address in rmt_addr:
                log_msg = "{}:{} TCP connection granted"
                self.logger.info(log_msg.format(*client_address))
                return True

            # Check if accept every port.
            client_addr, client_port = client_address
            for addr, port in rmt_addr:
                if port == 0 and client_addr == addr:
                    log_msg = "{}:{} TCP connection granted"
                    self.logger.info(log_msg.format(*client_address))
                    return True
            # rmt_addr is not empty but client_addres is not in there.
            log_msg = "{}:{} TCP connection refused"
            self.logger.info(log_msg.format(*client_address))
            return False

        # rmt_addr is empty.
        log_msg = "{}:{} TCP connection granted"
        self.logger.info(log_msg.format(*client_address))
        return True


    def serve_forever(self, poll_interval=0.5):
        """Override serve_forever for handle KeyboardInterrupt exceptions."""

        self.key_event.clear()
        try:
            ThreadingTCPServer.serve_forever(self, poll_interval)
        except KeyboardInterrupt as e:
            self.key_event.set()


# Setting logger.
def _set_logger(verbose = False, log = None, log_fmt = None, time_fmt = None):
    """Using logging module for setting a logger if needded. Returns Logger
    instance."""

    # Set log parameters.
    log_fmt = log_fmt or _LOG_FORMAT
    time_fmt = time_fmt or _TIME_FORMAT
    loglvl = logging.DEBUG if verbose else _NO_LOG
    logging.basicConfig(filename = log, level = loglvl, format = log_fmt,
                        datefmt= time_fmt)

    # Return Logger object.
    return logging.getLogger("SockServer")


def _handle_socksmanager(manager):
    """Running manager for operate SOCKS authentication and SOCKS requests
    with SocksManager."""

    try:
        if manager.socks_authenticate():
            manager.get_request()
    except socket.error as e:
        msg="Communication error while operating SOCKS client requests. {}"
        manager.logger.warning(msg.format(e.args[1]))
    except SocksException as e:
        msg="SOCKS error while operating SOCKS client requests. {}"
        manager.logger.warning(msg.format(e.msg))


# Using SocksManager for reverse connect to SOCKS client.
def reverse_server(server_address, client_address, version = V_SOCKS5,
                   user = None, pwd = None, verbose = False, log = None,
                   log_fmt = None, time_fmt = None):
    """Single threaded SOCKS server that reverse connect to SOCKS client."""

    logger = _set_logger(verbose, log, log_fmt, time_fmt)
    event = threading.Event()
    sock=socket.create_connection(client_address,source_address=server_address)
    manager = SocksManager(server_address,logger,sock,event,version,user,pwd)
    _handle_socksmanager(manager)
    manager.close_socket()
