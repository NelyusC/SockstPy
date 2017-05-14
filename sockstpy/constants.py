#-------------------------------------------------------------------------------
# Name:         constants.py
# Purpose:      This module define all SOCKS constants.
#
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------


# SOCKS consts from RFC1928.

# Ports
DEFAULT_PORT = 1080
DEFAULT_REVERSE_PORT = 51080

# Versions.
V_SOCKS4 = 4
V_SOCKS5 = 5

# Authintication methods.
AUTH_NONE = 0
AUTH_UPASS = 2
AUTH_NO_ACCEPTABLE = 255

# Socks commands.
CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP = 3

# Address types.
ADD_IPV4 = 1
ADD_IPV6 = 4
ADD_DOMAIN = 3

# SOCKS5 server replies.
REP_SUCCESS = 0
REP_GENERAL_FAILURE = 1
REP_CON_UNALLOWED = 2
REP_NET_UNREACH = 3
REP_HOST_UNREACH = 4
REP_CON_REFUSED = 5
REP_TTL_EXPIRED = 6
REP_CMD_NOT_SUPPORT = 7
REP_ADD_TYPE_UNSUPPORT = 8
REP_UNKNOWN_ERR = 9

# SOCKS4 server replies.
REP_REQ_GRANT = 90
REP_REQ_REJECT = 91
REP_CANT_CONN_IDENTD = 92
REP_DIFF_USERID = 93

# Consts tuples for helping validate data.
_VERSIONS = (V_SOCKS4, V_SOCKS5)
_AUTH_METHODS = (AUTH_NONE, AUTH_UPASS, AUTH_NO_ACCEPTABLE)
_CMD = (CMD_CONNECT, CMD_BIND, CMD_UDP)
_ADD_TYPES = (ADD_IPV4, ADD_IPV6, ADD_DOMAIN)
_SOCKS5_REPLIES =  (
                    REP_SUCCESS, REP_GENERAL_FAILURE, REP_CON_UNALLOWED,
                    REP_NET_UNREACH, REP_HOST_UNREACH, REP_CON_REFUSED,
                    REP_TTL_EXPIRED, REP_CMD_NOT_SUPPORT,
                    REP_ADD_TYPE_UNSUPPORT, REP_UNKNOWN_ERR
                    )
_SOCKS4_REPLIES =   (
                    REP_REQ_GRANT, REP_REQ_REJECT, REP_CANT_CONN_IDENTD,
                    REP_DIFF_USERID
                    )

