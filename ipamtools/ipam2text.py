#!/usr/bin/python3
"""
"""

# Initialize logger before importing myESX modules
import logging, sys, os

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
    from phpypamobjects import ipamServer, ipamAddress, ipamSubnet, ipamScanAgent
except ImportError as e:
    sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
    from phpypamobjects.phpypamobjects import ipamServer, ipamAddress, ipamSubnet, ipamScanAgent

import argparse
import signal
import textwrap
from typing import Optional

# Parameters of the program
class Parameters(argparse.Namespace):
    """Custom Parameters"""
    def __init__(self):
        super().__init__()
        self.progname:str = os.path.basename(sys.argv[0])
        self.debug = 0
        self.quiet:bool = False
        self.agentCode = os.getenv("SCANAGENT_CODE",'')
        path:str = os.getenv("HOME",".")

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
        self.cmdline_parser:argparse.ArgumentParser
        self.parser_vm:argparse.ArgumentParser
        self.init_cmdline_parser()
 
    def init_cmdline_parser(self):
        """Initialize the command line parser."""
        self.cmdline_parser = argparse.ArgumentParser(
            prog='myesxclient',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description = textwrap.dedent('''\
            This program creates a Virtual laboratory defines by a YAML file on a cluster of hipervisors.
            '''),
            )

        # Debug
        self.cmdline_parser.add_argument('-v', action='count', dest='debug', default=0, help='Increment detail of debugging messages.')
        # Quiet
        self.cmdline_parser.add_argument('-q', action='count', dest='quiet', default=0, help='Decrement detail of debugging messages.')
        # Arguments for IPAMservice
        self.cmdline_parser.add_argument('--ipam-url', metavar='url', dest='ipamURL', type=str, default='', help='URL of the IPAM service.')
        self.cmdline_parser.add_argument('--ipam-appid', metavar='appid', dest='ipamAppId', type=str, default='', help='Application ID for the IPAM service.')
        self.cmdline_parser.add_argument('--ipam-token', metavar='token', dest='ipamToken', type=str, default='', help='Application access token for the IPAM service.')
        self.cmdline_parser.add_argument('--ipam-user', metavar='user', dest='ipamUser', type=str, default='', help='Username for the IPAM service.')
        self.cmdline_parser.add_argument('--ipam-ca', metavar='ca', dest='ipamCAcert', type=str, default='', help='URL or Filename of a PEM file containing the public Certificate of the CA signing the server certificates of IPAM service.') 

        # Agent identity
        self.cmdline_parser.add_argument('-a', metavar='agentCode', dest='agentCode', type=str, required=False, help='Code to identify this scan agent.')

    def read_parameters(self, cmdline = None) -> Parameters:
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
            opts = global_parsers.cmdline_parser.parse_args(cmdline, namespace=opts)
        except argparse.ArgumentError as e:
            print("\nError parsing command line options:" + str(e))
            quit(1)
        return opts

###################################################################
# Aux IPAM functions
###################################################################    
def search_agent(ipam:ipamServer, code:str) -> Optional[ipamScanAgent]:
    # Read scan agents from IPAM server
    agents = ipam.getAllScanAgents()

    # Search agent with our code
    agent:Optional[ipamScanAgent] = None
    for a in agents:
        if a.getCode() == code:
            agent = a
    
    if not agent:
        return None
    else:
        return agent

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
# Main program    
###################################################################    
def main():    
    ##################################################################
    # Read parameters and initialize variables
    ##################################################################
    global global_parsers
    global parameters
    global_parsers = CMD_Parsers()
    parameters = global_parsers.read_parameters()

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
        # Connect to IPAM server and obtain agent description
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

        # Search agent by code
        if not parameters.agentCode:
            mylogger.error(f'No agent code specified')
            sys.exit(1)
        agent = search_agent(ipam=ipam, code=parameters.agentCode)
        if not agent:
            mylogger.error(f"Agent code '{parameters.agentCode}' not found at IPAM server.")
            sys.exit(1)

        mylogger.normal(f"Starting text dump {agent.getName()} ({agent.getType()}): {agent.getDescription()}")

        ##################################################################
        # Export loop
        ##################################################################

        subnets=ipam.getAllSubnets()
        for sn in subnets:
            try:
                # Skips folder subnets
                if sn.getisPool() == 0:
                    continue
                text = ipam.listSubnetPlain(sn)
                print(text)
            except Exception as e:
                if isinstance(e, GracefulEndException):
                    # Check gracefull end request if exceptions are disabled
                    if sighandler.kill_now:
                        break
                else:
                    mylogger.critical(f"Exception {e} listing subnet {sn.getDescription()}")

            if sighandler.kill_now:
                break

    ##################################################################
    # Daemon end requested
    ##################################################################
    except GracefulEndException as e:
        mylogger.warning(f"Daemon interrupted by exception {e.message}")

    mylogger.normal(f"{parameters.progname}: Ending")

if __name__ == "__main__":
    main()
