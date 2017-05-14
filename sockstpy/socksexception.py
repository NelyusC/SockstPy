#-------------------------------------------------------------------------------
# Name:         socksexception.py
# Purpose:      This module provides exception class concerning SOCKS
#               operations.
#
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------


class SocksException(Exception):
    """SOCKS general exception."""

    def __init__(self, msg, exc_err = None):
        """Initialize SOCKS exception."""

        self.msg = msg
        self.exc_err = exc_err

        if exc_err:
            self.msg = exc_err.message


    def __str__(self):
        return self.msg
