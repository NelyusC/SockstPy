#-------------------------------------------------------------------------------
# Name:         socks.py
# Purpose:      This module handle SOCKS messages parsing and generating.
#
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------

import socket
from struct import pack, unpack, unpack_from
from struct import error as struct_error

# Package modules.
from constants import *
from constants import _VERSIONS, _AUTH_METHODS, _CMD, _ADD_TYPES, \
    _SOCKS5_REPLIES, _SOCKS4_REPLIES
from socksexception import SocksException



class _BaseSocks(object):
    """Base SOCKS object with general methods for SOCKS operation."""


    def __init__(self, version = V_SOCKS5):
        """Initialize SOCKS parameters."""

        # SOCKS parameter check.
        if version not in _VERSIONS:
            raise SocksException("Wrong SOCKS version")

        # Instance attributes initialization.
        self.version = version


    def validate_version(self, rep_version, sndr, version = None):
        """Check SOCKS version in the response."""

        # Set default version if needed.
        version = version if version is not None else self.version

        if rep_version != version:
            raise SocksException("{0} has invalid SOCKS version".format(sndr))


    def _get_ipv6_hex(self, addr):
        """Return the hexadecimal representaion for ipv6.
        If the addres is invalid return None."""

        if not isinstance(addr, str):
            return None

        # Split to groups and padd with zeros.
        l_addr = [i.zfill(4) if i else i for i in addr.split(":")]

        # Grater than 8 groups is not a valid address.
        if len(l_addr) > 8:
            return None

        # Add zero groups if the address is zero compressed.
        for i in l_addr:
            if "" in l_addr:
                index = l_addr.index("")
                l_addr[index:index+1] = ["0000"]*(9-len(l_addr))
            else:
                break

        # Check each group.
        for i in l_addr:
            try:
                if not 0 <= int(i, 16) <= 65535:
                    return None
            except ValueError:
                return None

        return "".join(l_addr).decode("hex")


    def validate_addr(self, addr_type, addr):
        """Validate address by addr_type."""

        if type(addr) != str and addr_type not in _ADD_TYPES:
            return False

        if addr_type == ADD_IPV4:
            try:
                socket.inet_aton(addr)
            except:
                return False

        if addr_type == ADD_IPV6 and not self._get_ipv6_hex(addr):
            return False

        # The addres is valid or a domain name.
        # If it is a domain the socks server need to check access to this
        # domain therefore return true anyway.
        return True


    def validate_msg_params(self, addr_type, addr, port):
        """Validate message parameters."""

        if (addr_type in _ADD_TYPES and
                self.validate_addr(addr_type, addr) and  -1 < port < 65536):
            return True

        return False


    def get_addr_type(self, addr):
        """Return the address type of given address and None if the
        address is invalid."""

        for addr_type in _ADD_TYPES:
            if self.validate_addr(addr_type, addr):
                return addr_type

        return None


class Socks5(_BaseSocks):
    """This class handle all SOCKS5 packets and messages format."""

    # Class consts.
    _REPLIES = {
            REP_SUCCESS : "succeeded",
            REP_GENERAL_FAILURE : "general SOCKS server failure",
            REP_CON_UNALLOWED : "connection not allowed by ruleset",
            REP_NET_UNREACH : "network unreachable",
            REP_HOST_UNREACH : "host unreachable",
            REP_CON_REFUSED : "connection refused",
            REP_TTL_EXPIRED : "TTL expired",
            REP_CMD_NOT_SUPPORT : "command not supported",
            REP_ADD_TYPE_UNSUPPORT : "address type not supported",
            REP_UNKNOWN_ERR : "unknown error"
    }


    def __init__(self):
        """Initialize SOCKS5 parameters."""

        _BaseSocks.__init__(self, V_SOCKS5)


    def connect_message(self, auth = AUTH_NONE):
        """Generate message for connecting the SOCKS5 server."""

        # Set authentication message.
        conn_msg = pack("BBB", self.version , 1, auth)
        if auth != AUTH_NONE:
            conn_msg = pack("BBBB", self.version, 2, AUTH_NONE, auth)

        return conn_msg


    def parse_connect(self, request):
        """Parse connect message from SOCKS5 client. Returns a list
        with all SOCKS client supported authentication methods."""

        try:
            ver, nmethod = unpack_from("BB", request)
        except struct_error as e:
            raise SocksException("Invalid connect message from client")

        self.validate_version(ver, "Client")

        # Parse authentication methods.
        methods = []
        for i in xrange(nmethod):
            if ord(request[i+2]) in _AUTH_METHODS:
                methods.append(ord(request[i+2]))

        if not methods:
            methods.append(AUTH_NO_ACCEPTABLE)

        return methods


    def connect_reply(self, method):
        """Generate SOCKS5 server reply for connect requset."""

        return pack("BB", self.version, method)



    def parse_conn_reply(self, reply):
        """Parse SOCKS5 server reply for connect message."""

        if len(reply) != 2:
            raise SocksException("Server response is invalid")

        # Parse reply.
        self.validate_version(ord(reply[0]), "Server")

        if ord(reply[1]) == AUTH_NONE:
            return AUTH_NONE
        elif ord(reply[1]) == AUTH_UPASS:
            return AUTH_UPASS

        return AUTH_NO_ACCEPTABLE


    def client_auth(self, user, pwd):
        """Generate authentication message with user and password for
        connecting SOCKS5 server."""

        # Validate user and password.
        if not self.validate_user_pwd(user, pwd):
            raise SocksException("Invalid client authentication parameters")

        msg = pack("BB", 1, len(user)) + user
        if not pwd:
            return msg

        return msg + pack("B", len(pwd)) + pwd


    def parse_auth(self, msg):
        """Parse authentication message with user and password from
        SOCKS5 client."""

        try:
            version, user_len = unpack_from("BB", msg)
        except struct_error as e:
            raise SocksException("Invalid authentication message from client")
        self.validate_version(version, "Client", 1)

        # The password is the last byte of the message. therefore if we know
        # the length of the username we know where the password starts.
        user = msg[2:user_len]
        pwd = msg[3+user_len:]

        return user, pwd


    def auth_status(self, status):
        """Generates status message for client's authentication request."""

        return pack("BB", 1, status)


    def parse_server_auth(self, reply):
        """Parse server response for user:password authentication message."""

        if len(reply) != 2:
            raise SocksException("Server response is invalid")

        # Parse response.
        if ord(reply[0]) != 1:
            raise SocksException("Invalid data from the server")
        elif ord(response[1]) != 0:
                return False

        # Status is 0.
        return True


    def _generate_message(self, cmd, addr, port, addr_type,
                          version = None, frag = 0):
        """Generate a SOCKS5 message."""

        # Set default version of needed. Sometimes needed version 0.
        if version is None:
            version = self.version

        # Create message.
        msg = pack("BBBB", version, cmd, frag, addr_type)

        # Add address to the message.
        if addr_type == ADD_IPV4:
            msg += socket.inet_aton(addr)
        elif addr_type == ADD_IPV6:
            msg += self._get_ipv6_hex(addr)
        # Not IP then it is a domain name
        else:
            msg +=pack("B", len(addr)) + addr

        # Add port in network octet order.
        msg += pack("!H", port)
        return msg


    def generate_request(self, cmd, dst_addr, dst_port, addr_type):
        """Generate a SOCKS5 request that will be sent to the server."""

        # Parameters check.
        if (cmd not in _CMD or
                not self.validate_msg_params(addr_type, dst_addr, dst_port)):
            raise SocksException("Invalid client request parameters")

        return self._generate_message(cmd, dst_addr, dst_port, addr_type)


    def generate_udp(self, frag, dst_addr, dst_port, addr_type, data):
        """Generate UDP request header for sending UDP datagram.."""

        # Parameters check.
        if not self.validate_msg_params(addr_type, dst_addr, dst_port):
            raise SocksException("Invalid client request parameters")

        # Create message and add data.
        udp_msg=self._generate_message(0,dst_addr,dst_port,addr_type,0,frag)
        udp_msg += data

        return udp_msg


    def generate_reply(self, rep, bnd_addr, bnd_port, addr_type):
        """Generate a SOCKS5 reply that will be sent to the client."""

        # Parameters check.
        if (rep not in _SOCKS5_REPLIES or
                not self.validate_msg_params(addr_type, bnd_addr, bnd_port)):
            raise SocksException("Invalid server reply parameters")

        return self._generate_message(rep, bnd_addr, bnd_port, addr_type)


    def _parse_message(self, message):
        """Parse SOCKS5 messages."""

        # Parse the first 4 bytes.
        try:
            version, cmd, rsv, addr_type = unpack_from("BBBB", message)
        except struct_error as e:
            raise SocksException("Invalid SOCKS message received")

        # Get address.
        if addr_type not in _ADD_TYPES:
            raise SocksException("Server using unknown address type")
        if addr_type == ADD_IPV4:
            addr = socket.inet_ntoa(message[4:8])
        elif addr_type == ADD_IPV6:
            # Get every group of number from address remove hex "0x" prefix,
            # add zero padding and join with ":".
            addr = ":".join(hex(i).replace("0x","").zfill(4)
                            for i in unpack_from("!HHHHHHHH", message, 5))
        else:
            domain_len = ord(message[4])
            addr = message[5:5+domain_len]

        # Get port.
        port = unpack("!H", message[-2:])[0]

        # Validate message parameter.
        if not self.validate_msg_params(addr_type, addr, port):
            raise SocksException("Invalid message parameters received")
        return version, cmd, rsv, addr_type, addr, port


    def parse_reply(self, reply):
        """Parse the SOCKS5 server reply for a request."""

        # Parse reply.
        ver, rep, rsv, addr_type, b_addr, b_port = self._parse_message(reply)

        # Version check.
        self.validate_version(ver, "Server")

        # Get Reply.
        msg = self._REPLIES.get(rep, self._REPLIES[REP_UNKNOWN_ERR])

        return rep, msg, addr_type, b_addr, b_port


    def parse_request(self, req):
        """Parse the SOCKS5 client request."""

        # Parse request.
        ver, cmd, rsv, addr_type, dst_addr, dst_port = self._parse_message(req)

        # Version check.
        self.validate_version(ver, "Client")
        return cmd, addr_type, dst_addr, dst_port


    def parse_udp(self, dgram):
        """Parse the SOCKS5 client UDP datagram."""

        # For parsing request need to find where data starts.
        try:
            addr_type = ord(dgram[3])
            if addr_type == ADD_IPV4:
                data = dgram[10:]
            elif addr_type == ADD_IPV6:
                data = dgram[22:]
            else:
                data = dgram[7+ord(dgram[4]):]
        except IndexError as e:
            raise SocksException("Invalid SOCKS datagram received")

        # Parse the header.
        t_msg = self._parse_message(dgram[:-len(data)])
        ver, cmd, frag, addr_type, dst_addr, dst_port = t_msg

        # Version check.
        self.validate_version(ver, "Client", 0)

        # The cmd should be zero for UDP.
        if cmd != 0:
            raise SocksException("Invalid data from the server")

        return frag, addr_type, dst_addr, dst_port, data


class Socks4(_BaseSocks):
    """This class handle all SOCKS4 packets and messages format."""


    _REPLIES = {
            REP_REQ_GRANT : "request granted",
            REP_REQ_REJECT : "request rejected or failed",
            REP_CANT_CONN_IDENTD : "request rejected becasue SOCKS server "\
                                    "cannot connect to identd on the client",
            REP_DIFF_USERID : "request rejected because the client program "\
                                "and identd report different user-ids"
    }


    def __init__(self):
        """Initialize SOCKS5 parameters."""

        _BaseSocks.__init__(self, V_SOCKS4)


    def _generate_message(self, cmd, addr, port, version = None):
        """Generate a SOCKS5 message."""

        # Set default version of needed. Sometime need version 0 so check None.
        if version is None:
            version = self.version

        # Create message.
        msg = pack("!BBH", version, cmd, port)
        msg += socket.inet_aton(addr)

        return msg


    def generate_request(self, cmd, dst_addr, dst_port, userid):
        """Generate a SOCKS4 request that will be sent to the server."""

        # Parameters check.
        if (cmd not in _CMD or cmd == CMD_UDP or
                not self.validate_msg_params(ADD_IPV4, dst_addr, dst_port)):
            raise SocksException("Invalid client request parameters")

        # Create request message.
        req_msg = self._generate_message(cmd, dst_addr, dst_port)
        if userid:
            req_msg += userid
        req_msg += pack("B", 0)

        return req_msg


    def generate_reply(self, rep, dst_addr, dst_port):
        """Generate a SOCKS4 reply that will be sent to the client."""

        # Parameters check.
        if (rep not in _SOCKS4_REPLIES or
                not self.validate_msg_params(ADD_IPV4, dst_addr, dst_port)):
            raise SocksException("Invalid server reply parameters")

        return self._generate_message(rep, dst_addr, dst_port, 0)


    def _parse_message(self, messsage):
        """Parse SOCKS4 messages."""

        try:
            version, cmd, port = unpack_from("!BBH", messsage)
        except struct_error as e:
            raise SocksException("Invalid SOCKS message received")
        addr = socket.inet_ntoa(messsage[4:8])

        # Validate message parameter.
        if not self.validate_msg_params(ADD_IPV4, addr, port):
            raise SocksException("Invalid message parameters received")

        return version, cmd, addr, port


    def parse_reply(self, reply):
        """Parse the SOCKS4 server reply for a request."""

        version, rep, dst_addr, dst_port = self._parse_message(reply)

        # Version check. SOCKS4 reply version 0.
        self.validate_version(version, "Server", 0)

        # Get reply text.
        msg = self._REPLIES.get(rep,self._REPLIES[REP_REQ_REJECT])

        return rep, msg, dst_addr, dst_port


    def parse_request(self, request):
        """Parse the SOCKS4 client request."""

        version, cmd, dst_addr, dst_port = self._parse_message(request)

        # Version check.
        self.validate_version(version, "Client")

        # Get userid without Null in the end.
        userid = request[7:-1]

        return cmd, dst_addr, dst_port, userid


# Factory function.
def socks(version = V_SOCKS5, *args, **kwargs):
    """Returns SOCKS object that support the required version."""

    if version not in _VERSIONS:
        raise ValueError("Invallid SOCKS version")

    return Socks5() if version == V_SOCKS5 else Socks4()

