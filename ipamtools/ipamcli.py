#!/usr/bin/python3
"""
"""

# Initialize logger before importing myESX modules
from datetime import date, datetime, timedelta, timezone

from email.policy import default
import logging, sys, os
from tracemalloc import start

class Mylogging:
    NORMAL = int((logging.WARNING+logging.INFO)/2)
    VERBOSE = int((logging.INFO+logging.DEBUG)/2)
    DEVELOP = int((logging.DEBUG+logging.NOTSET)/2)

    def __init__(self):
        self.mylogger = logging.getLogger()
        logging.basicConfig(format='%(asctime)s:%(name)s:%(filename)s(line %(lineno)d)/%(funcName)s:%(levelname)s:%(message)s',stream=sys.stderr, level=logging.DEBUG)
        logging.addLevelName(self.NORMAL, 'NORMAL')
        logging.addLevelName(self.VERBOSE, 'VERBOSE')
        logging.addLevelName(self.DEVELOP, 'DEVELOP')

    def critical(self, msg, *args, **kwargs):
        self.mylogger.critical(msg=msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.mylogger.error(msg=msg, *args, **kwargs)
    def warning(self, msg, *args, **kwargs):
        self.mylogger.warning(msg=msg, *args, **kwargs)

    def normal(self, msg, *args, xtra=None, **kwargs):
        self.mylogger.log(level=Mylogging.NORMAL, msg=msg, *args, **kwargs)
    def info(self, msg, *args, **kwargs):
        self.mylogger.info(msg=msg, *args, **kwargs)

    def verbose(self, msg, *args, xtra=None, **kwargs):
        self.mylogger.log(level=Mylogging.VERBOSE, msg=msg, *args, **kwargs)
    def debug(self, msg, *args, **kwargs):
        self.mylogger.debug(msg=msg, *args, **kwargs)
    def develop(self, msg, *args, **kwargs):
        self.mylogger.log(level=Mylogging.DEVELOP, msg=msg, *args, **kwargs)
        
    def setLevel(self, level:int):
        self.mylogger.setLevel(level=level)
        for handler in self.mylogger.handlers:
            handler.setLevel(level)

mylogger = Mylogging()

try:
    from phpypamobjects import ipamServer, ipamAddress, ipamSubnet
except ImportError as e:
    sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
    from phpypamobjects.phpypamobjects import ipamServer, ipamAddress, ipamSubnet

import argparse
import shlex
import signal
import textwrap
import ipaddress
import re
import datetime
from typing import List, Optional, Required, Sequence, Tuple

if str(os.getenv("OS")) == "Windows_NT":
    mylogger.debug("Windows detected")
    import pyreadline3 as readline # type: ignore
else:
    import readline

# Parameters of the program
class Parameters(argparse.Namespace):
    """Parameters of the program, command line options and results of command line parsing."""
    commands = ["help","status","exit","quit","range","enable","disable"]
    # Subcommands for each command
    subcommands = {
                    'help':[],
                    'status':[],
                    'exit':[],
                    'quit':[],
                    'range':['help','ls','findbyname','register','unregister','annotate','age','usage'],
                    'enable':['unregister'],
                    'disable':['unregister'],
                    }

    """Custom Parameters"""
    def __init__(self):
        super().__init__()
        self.progname:str = os.path.basename(sys.argv[0])
        self.debug = 0
        self.quiet:bool = False
        path:str = os.getenv("HOME",".")
        self.clihistory:str = path + "/.esx_history"
        self.prompt:str = 'IPAMcli:: '
        self.command:str = ''
        self.pattern:str = ''
        self.subcommand:str = ''
        self.rangeStart:str = ''
        self.rangeEnd:str = ''
        self.enableopts:List[str] = []
        self.enabledOps = { 'unregister': False}

###################################################################
# Options and command parsers    
###################################################################    
class ErrorCatchingArgumentParser(argparse.ArgumentParser):
    def __init__(self, prog:str='', exit_on_error:bool=False, formatter_class=argparse.RawDescriptionHelpFormatter, description:str=''):
        super().__init__(prog=prog, exit_on_error=exit_on_error, formatter_class=formatter_class, description=description)
    def error(self, message=None):
        self.print_help()
        raise Exception(f'Parse error: {message}')
    def exit(self, status:int = 0, message:Optional[str] = None):
        raise Exception(f' ')
        #raise Exception(f'Parse error: {status} {message}')

class CMD_Parsers:
    """
    Custom object to store the two parsers used for this command (command line and cli) which share a common
        part to parse the subcommand syntax both from command line and console.
    """
    def __init__(self):
        """Initialize the two parsers and the common command parser."""
        self.cmdline_parser:argparse.ArgumentParser = self.init_options_parser()
 
    def init_options_parser(self) -> argparse.ArgumentParser:
        """Initialize the command line parser."""
        cmdline_parser = argparse.ArgumentParser(
            prog='myesxclient',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description = textwrap.dedent('''\
            This program creates a Virtual laboratory defines by a YAML file on a cluster of hipervisors.
            '''),
            )

        # Enable operations
        cmdline_parser.add_argument('-e', metavar='unregister', dest='enableopts', action='append', required=False, choices=Parameters.subcommands['enable'], type=str, help='Enable subsets of commands.') 
        # Debug
        cmdline_parser.add_argument('-v', action='count', dest='debug', default=0, help='Increment detail of debugging messages.')
        # Quiet
        cmdline_parser.add_argument('-q', action='count', dest='quiet', default=0, help='Decrement detail of debugging messages.')
        # Arguments for IPAMservice
        cmdline_parser.add_argument('--ipam-url', metavar='url', dest='ipamURL', type=str, default='', help='URL of the IPAM service.')
        cmdline_parser.add_argument('--ipam-appid', metavar='appid', dest='ipamAppId', type=str, default='', help='Application ID for the IPAM service.')
        cmdline_parser.add_argument('--ipam-token', metavar='token', dest='ipamToken', type=str, default='', help='Application access token for the IPAM service.')
        cmdline_parser.add_argument('--ipam-user', metavar='user', dest='ipamUser', type=str, default='', help='Username for the IPAM service.')
        cmdline_parser.add_argument('--ipam-ca', metavar='ca', dest='ipamCAcert', type=str, default='', help='URL or Filename of a PEM file containing the public Certificate of the CA signing the server certificates of IPAM service.') 

        return cmdline_parser

    def init_cli_parser(self) -> ErrorCatchingArgumentParser:
        """Initialize the cli parser."""
        # Build the CLI parser for commands from the CLI
        cli_parser = ErrorCatchingArgumentParser(
            prog='',
            exit_on_error=False,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description = textwrap.dedent('''\
            Each command has the syntax:
            command [subcommand] arguments ...
            '''),
            )
        return cli_parser

    def add_commands_to_parser(self, parent_parser:argparse.ArgumentParser) -> dict:

        subparsersList = {}
        # Subcommands
        subparsers = parent_parser.add_subparsers(title=sys.argv[0], dest='command', description=textwrap.dedent('''\
            CLI to manage IPAM service:
                Commands operate on the IPAM service database. Destructive commands are disabled by default and must be enabled with the enable command.
                Each command has the form:
                    <command> <subcommand> options ...      
                                                                                                                 
                Use the -h option after each command to get help about the available commands and options.
                The TAB key completes what you type showing the available options at any time.                                                                                                       
                ''')
        )

        # Host commands with no options
        subparsers.add_parser('help', help='Show help')
        subparsers.add_parser('status', help='Show current status')
        subparsers.add_parser('exit', help='End the CLI')
        subparsers.add_parser('quit', help='End the CLI')

        # Global commands
        parser_enable = subparsers.add_parser('enable', help='Enable dangerous operations.')
        parser_enable.add_argument('enablelevel', choices=Parameters.subcommands['enable'], type=str,
                                help=textwrap.dedent('''\
                These options enable operations of subsets of commands.
                ''')
        )
        parser_disable = subparsers.add_parser('disable', help='Disable dangerous operations.')
        parser_disable.add_argument('enablelevel', choices=Parameters.subcommands['disable'], type=str,
                                help=textwrap.dedent('''\
                These options disable operations of subsets of commands.
                ''')
        )

        # VM commands
        subparsersList['parser_range'] = subparsers.add_parser('range', help='Manage IP addresses in range.')
        subparsersList['parser_range'].add_argument('subcommand', choices=Parameters.subcommands['range'], type=str,
                                help=textwrap.dedent('''\
                This subcommands operate on IP addresses in range.
                ''')
        )
        
        return subparsersList

    def parse_cli_command(self, cmd:List[str]):
        parser = self.init_cli_parser()
        subparsersList = self.add_commands_to_parser(parser)

        parse_result = Parameters()
        try:
            cmd2, unknown = parser.parse_known_args(cmd, namespace=parse_result)
        except argparse.ArgumentError as e:
            print(str(e))
            return None
        except Exception as e:
            print(str(e))
            return None

        try:
            match parse_result.command:
                case 'range':
                    match parse_result.subcommand:
                        case 'help':
                            subparsersList['parser_range'].print_help()
                        case 'ls':
                            subparsersList['parser_range'].add_argument('rangeStart', type=str, help='Starting IP address.')
                            subparsersList['parser_range'].add_argument('rangeEnd', type=str, help='Ending IP address.')
                            subparsersList['parser_range'].add_argument('-m',           dest='lsMAC',         default=False, action='store_true', required=False, help='Show MAC addresses.')
                            subparsersList['parser_range'].add_argument('--mac',        dest='lsMAC',      default=False, action='store_true', required=False, help='Show MAC addresses.')
                            subparsersList['parser_range'].add_argument('-l',           dest='lslastSeen',    default=False, action='store_true', required=False, help='Show date this address was last seen.')
                            subparsersList['parser_range'].add_argument('--last',       dest='lslastSeen', default=False, action='store_true', required=False, help='Show date this address was last seen.')
                            subparsersList['parser_range'].add_argument('-g',           dest='lsAge',         default=False, action='store_true', required=False, help='Show time elapsed since last seen.')
                            subparsersList['parser_range'].add_argument('--age',        dest='lsAge',      default=False, action='store_true', required=False, help='Show time elapsed since last seen.')
                            subparsersList['parser_range'].add_argument('-d',           dest='lsDescription', default=False, action='store_true', required=False, help='Show description.')
                            subparsersList['parser_range'].add_argument('--description', dest='lsDescription', default=False, action='store_true', required=False, help='Show description.')
                            subparsersList['parser_range'].add_argument('-n',   dest='lsHostname', default=False, action='store_true', required=False, help='Show hostname.')
                            subparsersList['parser_range'].add_argument('--hostname',   dest='lsHostname', default=False, action='store_true', required=False, help='Show hostname.')
                            subparsersList['parser_range'].add_argument('-a',           dest='lsAll',       default=False, action="store_true", help='Show all information. Equivalent to -m -l -g -d -n.')
                            subparsersList['parser_range'].add_argument('--all',        dest='lsAll',       default=False, action="store_true", help='Show all information. Equivalent to -m -l -g -d -n.')
                            subparsersList['parser_range'].add_argument('--newer', type=int, default=None, required=False, help='Seen less than X days ago.')
                            subparsersList['parser_range'].add_argument('--older', type=int, default=None, required=False, help='Seen more than X days ago.')
                        case 'findbyname':
                            subparsersList['parser_range'].add_argument('rangeStart', type=str, help='Starting IP address.')
                            subparsersList['parser_range'].add_argument('rangeEnd', type=str, help='Ending IP address.')
                            subparsersList['parser_range'].add_argument('pattern', type=str, help='Search pattern.')
                        case 'register':
                            subparsersList['parser_range'].add_argument('rangeStart', type=str, help='Starting IP address.')
                            subparsersList['parser_range'].add_argument('rangeEnd', type=str, help='Ending IP address.')
                        case 'unregister':
                            subparsersList['parser_range'].add_argument('rangeStart', type=str, help='Starting IP address.')
                            subparsersList['parser_range'].add_argument('rangeEnd',     type=str, help='Ending IP address.')
                            subparsersList['parser_range'].add_argument('-o',      type=int, default=None, required=False, help='Only unregister addresses seen more than X days ago.')
                            subparsersList['parser_range'].add_argument('--older',      type=int, default=None, required=False, help='Only unregister addresses seen more than X days ago.')
                            subparsersList['parser_range'].add_argument('-n',      type=int, default=None, required=False, help='Only unregister addresses seen less than X days ago.')
                            subparsersList['parser_range'].add_argument('--newer',      type=int, default=None, required=False, help='Only unregister addresses seen less than X days ago.')
                            subparsersList['parser_range'].add_argument('-a',      type=int, default=1,    required=False, help='If there are addresses seen less than X days ago, refuse unregistering any address. Default is 1 day.')
                            subparsersList['parser_range'].add_argument('--alive',      type=int, default=1,    required=False, help='If there are addresses seen less than X days ago, refuse unregistering any address. Default is 1 day.')
                            subparsersList['parser_range'].add_argument('-f',           dest='forceUnregister', default=False, action='store_true', required=False, help='Force unregistering the range even if there are recently seen addresses (not needed when using --older or --newer).')
                        case 'annotate':
                            subparsersList['parser_range'].add_argument('rangeStart', type=str, help='Starting IP address.')
                            subparsersList['parser_range'].add_argument('rangeEnd', type=str, help='Ending IP address.')
                            subparsersList['parser_range'].add_argument('annotation', type=str, help='Description.')
                        case 'age':
                            subparsersList['parser_range'].add_argument('rangeStart', type=str, help='Starting IP address.')
                            subparsersList['parser_range'].add_argument('rangeEnd', type=str, help='Ending IP address.')
                            subparsersList['parser_range'].add_argument('-m',           dest='lsMAC',         default=False, action='store_true', required=False, help='Show MAC addresses.')
                            subparsersList['parser_range'].add_argument('--mac',        dest='lsMAC',      default=False, action='store_true', required=False, help='Show MAC addresses.')
                            subparsersList['parser_range'].add_argument('-l',           dest='lslastSeen',    default=False, action='store_true', required=False, help='Show date this address was last seen.')
                            subparsersList['parser_range'].add_argument('--last',       dest='lslastSeen', default=False, action='store_true', required=False, help='Show date this address was last seen.')
                            subparsersList['parser_range'].add_argument('-g',           dest='lsAge',         default=False, action='store_true', required=False, help='Show time elapsed since last seen.')
                            subparsersList['parser_range'].add_argument('--age',        dest='lsAge',      default=False, action='store_true', required=False, help='Show time elapsed since last seen.')
                            subparsersList['parser_range'].add_argument('-d',           dest='lsDescription', default=False, action='store_true', required=False, help='Show description.')
                            subparsersList['parser_range'].add_argument('--description', dest='lsDescription', default=False, action='store_true', required=False, help='Show description.')
                            subparsersList['parser_range'].add_argument('-n',   dest='lsHostname', default=False, action='store_true', required=False, help='Show hostname.')
                            subparsersList['parser_range'].add_argument('--hostname',   dest='lsHostname', default=False, action='store_true', required=False, help='Show hostname.')
                            subparsersList['parser_range'].add_argument('-a',           dest='lsAll',       default=False, action="store_true", help='Show all information. Equivalent to -m -l -g -d -n.')
                            subparsersList['parser_range'].add_argument('--all',        dest='lsAll',       default=False, action="store_true", help='Show all information. Equivalent to -m -l -g -d -n.')
                        case 'usage':
                            subparsersList['parser_range'].add_argument('rangeStart', type=str, help='Starting IP address.')
                            subparsersList['parser_range'].add_argument('rangeEnd', type=str, help='Ending IP address.')
                            
            parse_result = parser.parse_args(cmd, namespace=parse_result)
                    
        except argparse.ArgumentError as e:
            print(str(e))
            return None
        except Exception as e:
            print(str(e))
            return None
                    
        return parse_result

def read_parameters(cmdline = None) -> Parameters:
    """"Create a data structure to hold parameters of the program.
    
    Parameters are initialized from many sources (configuration files, environment variables) and then overwriten
    by options from the command line.
    
    - cmdline: an array with the command line split in words
    """
        
    # Initialize empty parameters
    opts = Parameters()

    # Read options from command line
    try:
        # Parse command line arguments into parameters Namespace
        global_parsers.cmdline_parser.parse_args(cmdline, namespace=opts)
        # Check enabled subcommand options specified in command line
        for level in opts.enableopts:
            if level == 'all':
                for op in opts.enabledOps:
                    opts.enabledOps[op] = True
                    mylogger.debug (f'{op} enabled.')
            else:
                opts.enabledOps[level] = True
                mylogger.debug (f'{level} enabled.')
        
    except argparse.ArgumentError as e:
        print("\nError parsing command line options:" + str(e))
        quit(1)
    return opts

def split_into_words(text):
    """
    Split a command line into words using shlex, respecting quotes and escaped spaces.
    
    :param text: Command line string to be split into words.
    :return: List of words.
    """
    lex = shlex.shlex(text, posix=True)
    lex.whitespace_split = True
    lex.quotes = '"\''
    lex.commenters = '#'
    return list(lex)

def read_cli() -> Optional[Parameters]:
    """
    Read from terminal with readline (line editing) and parse the command line.
    If the user enters EOF (Control-D) or interrupts (Control-C), an EOFError is raised.

    :return: Parameters object with the parsed command or None if there was an error.
    """
    try:
        commandline = input(parameters.prompt)
    except KeyboardInterrupt as kb:
        print("\n<INTR>")
        raise EOFError from kb
    except EOFError as eof:
        print("\nexit")
        raise
    except Exception as e:
        mylogger.error("Error reading command line: " + str(e))
        return None

    # Split into an array of words
    try:
        cmd = split_into_words(commandline)
    except Exception as e:
        mylogger.error("Invalid command line: " + str(e))
        return None
        
    command = global_parsers.parse_cli_command(cmd)

    #mylogger.debug("Parsed command:" + str(command))
    return command


###################################################################
# Signals handler
###################################################################    
class GracefulEndException(Exception):
    """Ending program with a message."""
    def __init__(self, message="Graceful termination invoked", log = False):
        self.message = message
        super().__init__(self.message)
        if log:
            mylogger.error(message)

class GracefulKiller:
    kill_now = False
    interrupt_me = True

    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        self.kill_now = True
        if self.interrupt_me:
            raise GracefulEndException(f"{signum}")

    def allowInterrupt(self):
        self.interrupt_me = True

    def forbidInterrupt(self):
        self.interrupt_me = False

###################################################################
# Command execution
###################################################################    
def is_valid_regex(pattern):
    """Check the validity of regular expressions before sending them to the API"""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False

        
def print_ls_address(cmd:Parameters, addr:ipamAddress):
    last_seen = addr.getLastSeen()
    if last_seen:
        age = (datetime.datetime.now(last_seen.tzinfo) - last_seen)
        age_info = f'{age.days}days-{age.seconds // 3600}:{(age.seconds // 60) % 60:02d} ago'
        date_info = str(last_seen)
    else:
        age_info = 'never seen'
        date_info = 'never seen'
    if addr.getHostname():
        host_info = addr.getHostname()
    else:
        host_info = ''

    # Check shown 
    date_info = f' {date_info:25}' if cmd.lslastSeen or cmd.lsAll else ''
    age_info = f' {age_info:>17}' if cmd.lsAge or cmd.lsAll else ''
    mac_info = f' {str(addr.getMac()):17} ' if cmd.lsMAC or cmd.lsAll else ''
    host_info = f' {host_info:<20} ' if cmd.lsHostname or cmd.lsAll else ''
    descr_info = f' {addr.getDescription()} ' if cmd.lsDescription or cmd.lsAll else ''

    print(f'{str(addr):15}{date_info}{age_info}{mac_info}{host_info}{descr_info}')

def unregister_range(server:ipamServer, addresses:List, cmd:Parameters):
    unregCNT:int = 0
    for ip in addresses:
        mylogger.debug(f'Processing IP {ip}')
        matching_addresses = server.findIPs(ip)
        # Check if address is registered
        if matching_addresses == []:
            mylogger.info(f'== {ip} address not registered ==')
            continue
        # Unregister addresses if --newer or --older filters are met
        for addr in matching_addresses:
            mylogger.info(f'== Unregistering address {ip} ==')
            if parameters.enabledOps['unregister']:
                server.unregisterIP(addr)
                unregCNT += 1
            else:
                mylogger.warning("unregister command disabled for security. Enable it with 'enable unregister'.")
    mylogger.info(f'== Unregistered {unregCNT} addresses ==')


def execute_range(server:ipamServer, cmd:Parameters):
    """
    Execute all kind of VM management subcommands.
    
     -cmd: The current command structure resulting from parsing cmd line.  
    """
    # ls command
    if cmd.subcommand == 'ls':
        start_ip = ipaddress.ip_address(cmd.rangeStart)
        end_ip = ipaddress.ip_address(cmd.rangeEnd)
        mylogger.debug(f'ls {start_ip} {end_ip}')
        addresses = [ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1)]
        for ip in addresses:
            mylogger.debug(f'Processing IP {ip}')
            matching_addresses = server.findIPs(ip)
            # Check if address is registered
            if matching_addresses == []:
                mylogger.info(f'== {ip} address not registered ==')
                continue
            for addr in matching_addresses:
                last_seen = addr.getLastSeen()
                # Check for age filters
                if last_seen:
                    age = (datetime.datetime.now(last_seen.tzinfo) - last_seen)
                    if cmd.newer and age > timedelta(days=cmd.newer):
                        continue
                    if cmd.older and age < timedelta(days=cmd.older):
                        continue
                else:
                    if cmd.newer:
                        continue
                # Print address attributes
                print_ls_address(cmd, addr)

    # age command
    if cmd.subcommand == 'age':
        start_ip = ipaddress.ip_address(cmd.rangeStart)
        end_ip = ipaddress.ip_address(cmd.rangeEnd)
        mylogger.debug(f'age {start_ip} {end_ip}')
        addresses = [ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1)]
        oldest_address:Optional[ipamAddress] = None
        youngest_address:Optional[ipamAddress] = None
        for ip in addresses:
            mylogger.debug(f'Processing IP {ip}')
            matching_addresses:Sequence[ipamAddress] = server.findIPs(ip)
            # Check if address is registered
            if matching_addresses == []:
                mylogger.info(f'== {ip} address not registered ==')
                continue
            for addr in matching_addresses:
                last_seen = addr.getLastSeen()
                # Check for age filters
                if last_seen:
                    if not youngest_address or last_seen > youngest_address.getLastSeen():
                        youngest_address = addr
                    if not oldest_address or last_seen < oldest_address.getLastSeen():
                        oldest_address = addr
                else:
                    continue
        if oldest_address:
            print("Oldest address: ", end='')
            print_ls_address(cmd, oldest_address)
        if youngest_address:
            print("Youngest address: ", end='')
            print_ls_address(cmd, youngest_address) 

    # usage command
    if cmd.subcommand == 'usage':
        start_ip = ipaddress.ip_address(cmd.rangeStart)
        end_ip = ipaddress.ip_address(cmd.rangeEnd)
        mylogger.debug(f'usage {start_ip} {end_ip}')
        addresses = [ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1)]
        free = 0
        used = 0
        for ip in addresses:
            mylogger.debug(f'Processing IP {ip}')
            matching_addresses = server.findIPs(ip)
            # Check if address is registered
            if matching_addresses == []:
                mylogger.debug(f'Address {ip} is free')
                free += 1
                continue
            else:
                mylogger.info(f'Address {ip} is registered')
                used += 1
        print(f'Usage of range {start_ip} - {end_ip}: {free} free, {used} registered')

    # unregister command
    if cmd.subcommand == 'unregister':
        start_ip = ipaddress.ip_address(cmd.rangeStart)
        end_ip = ipaddress.ip_address(cmd.rangeEnd)
        mylogger.debug(f'unregister {start_ip} {end_ip}')
        addresses = [ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1)]
        aliveCNT:int = 0
        unregisteredCNT:int = 0
        for ip in addresses:
            mylogger.debug(f'Processing IP {ip}')
            matching_addresses = server.findIPs(ip)
            # Check if address is registered
            if matching_addresses == []:
                mylogger.info(f'== {ip} address not registered ==')
                continue
            # Unregister addresses if --newer or --older filters are met
            for addr in matching_addresses:
                last_seen = addr.getLastSeen()
                # Check for age filters
                if last_seen:
                    age = (datetime.datetime.now(last_seen.tzinfo) - last_seen)
                    if cmd.newer:
                        if age < timedelta(days=cmd.newer):
                            # Unregister only addresses seen less than X days ago
                            mylogger.info(f'== {ip} address seen {age.days} days ago, unregistering ==')
                            if parameters.enabledOps['unregister']:
                                server.unregisterIP(addr)
                                unregisteredCNT += 1
                            else:
                                mylogger.warning("unregister command disabled for security. Enable it with 'enable unregister'.")
                        else:
                            continue
                    if cmd.older:
                        if age > timedelta(days=cmd.older):
                            # Unregister only addresses seen more than X days ago
                            mylogger.info(f'== {ip} address seen {age.days} days ago, unregistering ==')
                            if parameters.enabledOps['unregister']:
                                server.unregisterIP(addr)
                                unregisteredCNT += 1
                            else:
                                mylogger.warning("unregister command disabled for security. Enable it with 'enable unregister'.")
                        else:
                            continue
                    # If no --newer or --older, count alive addresses
                    if not cmd.newer and not cmd.older:
                        if age < timedelta(days=cmd.alive):
                            mylogger.info(f'== {ip} address seen {age.days} days ago ==')
                            aliveCNT += 1
                else:
                    if cmd.older:
                        # Unregister never seen addresses
                        mylogger.info(f'== {ip} address never seen, unregistering ==')
                        if parameters.enabledOps['unregister']:
                            server.unregisterIP(addr)
                            unregisteredCNT += 1
                        else:
                            mylogger.warning("unregister command disabled for security. Enable it with 'enable unregister'.")

        if cmd.newer or cmd.older:
            if unregisteredCNT == 0:
                mylogger.warning(f'== No addresses to unregister in range {start_ip} - {end_ip} ==')
            else:
                mylogger.warning(f'== {unregisteredCNT} addresses unregistered in range {start_ip} - {end_ip} ==')
            return
        
        if not cmd.newer and not cmd.older and aliveCNT > 0 and not cmd.forceUnregister:
            mylogger.error(f'== There are {aliveCNT} addresses seen less than {cmd.alive} days ago. Use -f option to force unregistering the range. No address has been unregistered. ==')
            return
        if not cmd.newer and not cmd.older and aliveCNT == 0:
            mylogger.warning(f'== No addresses seen less than {cmd.alive} days ago. Unregistering the range. ==')
            unregister_range(server, addresses, cmd)
        if not cmd.newer and not cmd.older and cmd.forceUnregister:
            mylogger.warning(f'== -f option added. Unregistering the range. ==')
            unregister_range(server, addresses, cmd)


def execute_command(ipam:ipamServer, cmd:Parameters):
    """Decode and execute commands.
    
    Parameters:
    -ipam: IPAM server.
    -cmd: Structure with command and arguments to execute.
    
    Return:
    -False means that the program must end.
    -True means that the program can continue.
    """

    mylogger.debug(">>>COMMAND>>> "+str(cmd))
    
    # Check if regexp syntax is OK in some commands
    if cmd.command in ['ls','power', 'snapshot'] and not is_valid_regex(cmd.pattern):
        mylogger.error(f'Regular expression {cmd.pattern} has invalid syntax.')
        return True

    # Execute local commands
    match cmd.command:
        case 'quit' | 'exit':
            return False
        case 'help':
            parser = global_parsers.init_cli_parser()
            global_parsers.add_commands_to_parser(parser)
            parser.print_help()
            return True
        case 'enable':
            if cmd.enablelevel == 'all':
                for op in parameters.enabledOps:
                    parameters.enabledOps[op] = True
                    print (f'{op} enabled.')
            else:
                parameters.enabledOps[cmd.enablelevel] = True
                print (f'{cmd.enablelevel} enabled.')
            return True
        case 'disable':
            if cmd.enablelevel == 'all':
                for op in parameters.enabledOps:
                    parameters.enabledOps[op] = False
                    print (f'{op} disabled.')
            else:
                parameters.enabledOps[cmd.enablelevel] = False
                print (f'{cmd.enablelevel} disabled.')
            return True
        
    if cmd.command in parameters.enabledOps and re.match(r'(start|ls|lsds)', cmd.subcommand) == None:
        if not parameters.enabledOps[cmd.command]:
            mylogger.error(f"Command ignored: The '{cmd.command} {cmd.subcommand}' command is disabled for security. Enable it with the 'enable {cmd.command}' command.")
            return True


    match cmd.command:
        case "range":
            execute_range(ipam, cmd)
                    
    # Continue execution
    return True

###################################################################
# Autocompleter    
###################################################################    
COMPLETER_DICT:List[Tuple[str, List[str]]] = []
for cmd in Parameters.subcommands:
    COMPLETER_DICT.append((cmd, Parameters.subcommands[cmd]))

def lookup(command:str, subcommand:str, dict:List[Tuple[str, List[str]]]):
    listcmd = [cmd for cmd,_ in COMPLETER_DICT if cmd.startswith(command)]
    listsubcmd:List[str] = []

    if not listcmd:
        listcmd = [cmd for cmd,_ in COMPLETER_DICT]

    if len(listcmd) == 1:
        listsubcmd = [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == listcmd[0] and subcmd.startswith(subcommand) ]
        if not listsubcmd:
            listsubcmd = [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == listcmd[0] ]

    return listcmd,listsubcmd

# Autocompletion function
def completer3(text, state) ->Optional[str]:
    split_regexp=r'([a-z]+)( *)(\-[a-z]|[a-z]*)( *)'
    buffer:str = readline.get_line_buffer() # type: ignore
    tokens = buffer.split()
    parse_res=re.match(split_regexp,buffer)
    if not parse_res:
        token1=''
        token2=''
        token3=''
        token4=''
    else:
        token1=parse_res.group(1)
        token2=parse_res.group(2)
        token3=parse_res.group(3)
        token4=parse_res.group(4)

    #print(f"COMPLETER: token1='{token1}' token2='{token2}' token3='{token3}' token4='{token4}'")
    lcmd,lsubcmd = lookup(token1,token3, COMPLETER_DICT)
    #print(f"COMPLETER: lcmd={lcmd} lsubcmd={lsubcmd}")

    matches = []
    # If no tokens, complete commands
    if not token1:
        matches = lcmd

    # If one token and no space after it
    elif token1 and not token2:
        # Check if first token is already a word in dictionary or complete
        if len(lcmd) == 1 and token1 == lcmd[0]:
            # Command is completed and we can complete space and start completing next level
            readline.insert_text(' ') # type: ignore
            matches = []
        else:
            matches = lcmd

    # Now complete token3
    elif token1 and token2:
        if not token3:
            matches = [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == token1]
        elif token3 and not token4:
            # Check if second token is already a word in dictionary or complete
            if [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == token1 and subcmd == token3 ]:
                # Command is completed and we can complete space and start completing next level
                readline.insert_text(' ') # type: ignore
                matches = []
            else:
                matches = [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == token1 and subcmd.startswith(text) ]
                if not matches:
                    matches = [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == token1]
                
        
    # Return the match at the current state
    if state < len(matches):
        #print(f"RETURN {matches[state]}")
        return matches[state]
    else:
        #print(f"RETURN NONE")
        return None

# Autocompletion function
def completer(text, state) ->Optional[str]:
    split_regexp=r'([a-z]+)( *)([a-z-*.]*)( *)'
    buffer:str = readline.get_line_buffer() # type: ignore
    tokens = buffer.split()
    parse_res=re.match(split_regexp,buffer)
    if not parse_res:
        token1=''
        token2=''
        token3=''
        token4=''
    else:
        token1=parse_res.group(1)
        token2=parse_res.group(2)
        token3=parse_res.group(3)
        token4=parse_res.group(4)

    #print(f"COMPLETER: token1='{token1}' token2='{token2}' token3='{token3}' token4='{token4}'")
    # If no tokens, complete commands
    if not token1:
        matches = [cmd for cmd,_ in COMPLETER_DICT if cmd.startswith(text)]

    # If one token and no space after it
    elif token1 and not token2:
        # Check if first token is already a word in dictionary or complete
        if [cmd for cmd,_ in COMPLETER_DICT if cmd==token1]:
            # Command is completed and we can complete space and start completing next level
            readline.insert_text(' ') # type: ignore
            matches = []
        else:
            matches = [cmd for cmd,_ in COMPLETER_DICT if cmd.startswith(text)]
            if not matches:
                matches = [cmd for cmd,_ in COMPLETER_DICT]

    # Now complete token3
    elif token1 and token2:
        if not token3:
            matches = [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == token1]
        elif token3 and not token4:
            # Check if second token is already a word in dictionary or complete
            if [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == token1 and subcmd == token3 ]:
                # Command is completed and we can complete space and start completing next level
                readline.insert_text(' ') # type: ignore
                matches = []
            else:
                matches = [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == token1 and subcmd.startswith(text) ]
                if not matches:
                    matches = [subcmd for cmd,subdict in COMPLETER_DICT for subcmd in subdict if cmd == token1]
                
        
    # Return the match at the current state
    if state < len(matches): # type: ignore
        #print(f"RETURN {matches[state]}")
        return matches[state] # type: ignore
    else:
        #print(f"RETURN NONE")
        return None


###################################################################
# Main program    
###################################################################    
def main():    
    ##################################################################
    # Read parameters and initialize variables
    ##################################################################
    global global_parsers
    global parameters
    global_parsers = CMD_Parsers()
    parameters = read_parameters()

    # Default level is warning
    level = mylogger.NORMAL
    # More -v activate additional messages and more -q disable messages
    level = level + 5 * (parameters.quiet-parameters.debug)
    if level < mylogger.DEVELOP:
        level = mylogger.DEVELOP
    if level > logging.CRITICAL:
        level = logging.CRITICAL
    mylogger.setLevel(level)

    mylogger.debug(f"{parameters.progname}: Starting with parameters: {parameters}")

    # Prepare handler for termination signals
    sighandler = GracefulKiller()
    ##################################################################
    # All of this is exited gracefully
    ##################################################################
    try:

        ##################################################################
        # Connect to IPAM server
        ##################################################################
        try:
            mylogger.verbose("Connecting IPAM server")
            ipam = ipamServer(
                url=parameters.ipamURL,
                app_id=parameters.ipamAppId,
                token=parameters.ipamToken,
                user=parameters.ipamUser,
                password='',
                cacert=parameters.ipamCAcert
            )
        except Exception as e:
            mylogger.error(f'Connection to IPAM server {parameters.ipamURL} failed: {e}')
            sys.exit(1)
        mylogger.normal("Connected to IPAM server")

        ##################################################################
        # Read CLI and execute commands
        ##################################################################

        try:
            # Configure line edition
            readline.read_history_file(parameters.clihistory) # type: ignore
            readline.set_completer(completer) # type: ignore
            readline.parse_and_bind("tab: complete") # type: ignore

        except Exception:
            pass

        while True:
            try:
                cmd = read_cli()
            except EOFError:
                break
            except Exception:
                break

            if not cmd or not cmd.command:
                #print("No valid command read")
                continue
            # If execute_command returns false we exit
            if not execute_command(ipam, cmd):
                break

        readline.write_history_file(parameters.clihistory) # type: ignore
            



    ##################################################################
    # Daemon end requested
    ##################################################################
    except GracefulEndException as e:
        mylogger.warning(f"Daemon interrupted by exception {e.message}")

    mylogger.normal(f"{parameters.progname}: Ending")

if __name__ == "__main__":
    main()
