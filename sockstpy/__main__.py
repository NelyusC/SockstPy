#-------------------------------------------------------------------------------
# Name:         sockstpy.__main__
# Purpose:      This module handle SOCKS communication and SOCKS tunneling.
#
#
# Author:      Nethanel Coppenhagen
#
#-------------------------------------------------------------------------------

import sys
import time
import socket
import argparse

from socksclient import SocksClient
from socksexception import SocksException
from sockserver import SockServer, reverse_server
from constants import V_SOCKS4, V_SOCKS5, _VERSIONS


class Address(argparse.Action):
    """Supplies IP:PORT or IP:PORT, IP:PORT, IP:PORT parsing action."""

    def __call__(self, parser, namesapce, values, option_string = None):
        """Parse IP:PORT string into tupple ('address', port). If there is
        IP:PORT, IP:PORT string parse into list of tuples."""

        values = values[0]
        addr_list = values.split(",")
        addr_list = [i.strip() for i in addr_list]
        chain_address =[]
        for address in addr_list:
            addr, port = address.split(":")
            chain_address.append((addr, int(port)))

        if len(chain_address) == 1:
            setattr(namesapce, self.dest, chain_address[0])
        else:
            setattr(namesapce, self.dest, chain_address)


def _set_parent_parser():
    """Sets default arguments for the parser."""

    parent = argparse.ArgumentParser(add_help = False)
    parent.add_argument("-V", action = "store", default = V_SOCKS5, type=int,
                        choices=_VERSIONS,metavar = "4|5", dest = "version",
                        help="SOCKS versions. default is socks5")
    parent.add_argument("-U", "--user", action = "store", default = None,
                        type=str, metavar="USER",
                        help="username for SOCKS authentication if needed")
    parent.add_argument("-P", "--pass", action = "store", default = None,
                        type=str, metavar="PASS", dest = "pwd",
                        help="username for SOCKS authentication if needed")
    parent.add_argument("local_address", nargs = 1, action = Address,
                        help = "local address for forwarding to server")
    return parent


def _set_client_parser(client_parser):
    """Sets arguments for SOCKS client."""

    client_parser.add_argument("-u", "--udp", action = "store_true",
                               help = "Use UDP protocol (default is TCP)")
    client_parser.add_argument("-r", action="store", type=int, metavar="port",
                               dest="reverse", default=0,
                               help="Wait for reverse connection from SOCKS "\
                               "server to port.")
    client_parser.add_argument("socks_servers", nargs = 1, action = Address,
                               help = "address of SOCKS server can be more"\
                               "than one in the format IP:port,IP:port "\
                               "WITHOUT SPACES!!!")
    client_parser.add_argument("remote_address", nargs = 1, action = Address,
                               help = "target remote address")


def _set_server_parser(server_parser):
    """Sets arguments for SOCKS server."""

    server_parser.add_argument("-v", action = "store_true", dest="verbose",
                               help="Set verbosity. If log specified written "\
                               "to log file.")
    server_parser.add_argument("-l", action="store", dest="log", default=None,
                               help="If verbosity is set write to log file.")
    server_parser.add_argument("-r", nargs=1, action=Address, default=None,
                               dest="reverse",metavar = "remote_addres",
                               help="Reverse connection to SOCKS client")
    server_parser.add_argument("-f", nargs = 1, action = Address, default = [],
                               dest="whitelist",help="address of acceptable "\
                               "SOCKS client that allowed to connect. If no "\
                               "address supplied accept every connection. "\
                               "can be more than one address in the format "\
                               "IP:port,IP:port WITHOUT SPACES!!!. "\
                               "Ignored on reverse connection.")


def _set_args():
    """Sets arguments parser."""

    parser = argparse.ArgumentParser(usage = "sockstpy [client | server] [-h]")
    parent = _set_parent_parser()
    subparsers = parser.add_subparsers(dest = "runtype",
                                       metavar = "[client | server]")

    # Set specific arguments for client or server.
    client_parser = subparsers.add_parser("client", prog = "sockstpy client",
                                          parents = [parent],
                                          help="Run as SOCKS client")
    _set_client_parser(client_parser)
    server_parser = subparsers.add_parser("server", prog = "sockstpy server",
                                          parents = [parent],
                                          help="Run as SOCKS server")
    _set_server_parser(server_parser)

    return parser


def run_client(args):
    """Run SockstPy client."""

    # Check if socks_servers is chain.
    if isinstance(args.socks_servers, list):
        socks_chain = args.socks_servers
    else:
        socks_chain = [args.socks_servers]
    client = SocksClient(args.local_address, args.remote_address, socks_chain,
                         args.udp, args.version, args.user,args.pwd)

    # Connect SOCKS server.
    if args.reverse:
        msg = "SockstPy: Wait for reverse connection at port: {}."
        print msg.format(args.reverse)
        client.reverse_connect(args.reverse)
    else:
        msg = "SockstPy: Connecting SOCKS servers."
        print msg.format(args.reverse)
        client.connect_socks_chain()

    # Start forwarding.
    msg = "SockstPy: Start forwrding to SOCKS server from {}:{}."
    print msg.format(*args.local_address)
    if args.udp:
        client.udp_forward()
    else:
        client.tcp_forawrd()

    client.close_sockets()


def run_server(args):
    """Run SockstPy server."""

    # Reverse connection to SOCKS client.
    if args.reverse:
        msg = "SockstPy: Reverse connect to {}:{}."
        print msg.format(*args.reverse)
        reverse_server(args.local_address, args.reverse, args.version,
                       args.user, args.pwd, args.verbose, args.log)

    # Run as server. Wait for connections
    else:
        msg = "SockstPy: Start SOCKS server at {}:{}."
        print msg.format(*args.local_address)
        server = SockServer(args.local_address, version = args.version,
                            rmt_addr = args.whitelist, user =args.user,
                            pwd = args.pwd, verbose = args.verbose,
                            log = args.log)
        server.serve_forever()


def main():

    # Set Command line arguments.
    parser = _set_args()
    try:
        args = parser.parse_args()
    except ValueError as e:
        print "Invalid options.",
        print "Please try \"sockstpy [client | server] -h\" for usage and options."
        sys.exit(1)

    try:
        if args.runtype == "client":
            run_client(args)
        else:
            run_server(args)
    except socket.error as e:
        print "SockstPy: Communication error. {}".format(e.args[1])
    except SocksException as e:
        print "SockstPy: Socks error. {}".format(e.msg)
    except KeyboardInterrupt, SystemExit:
        pass
    finally:
        time.sleep(0.2)
        print "SockstPy: QUITTING."

if __name__ == '__main__':
    main()

