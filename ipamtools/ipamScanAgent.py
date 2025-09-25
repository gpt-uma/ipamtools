#!/usr/bin/python3
"""
This project is a Python script that manages virtual laboratories on a cluster of hypervisors.
It uses YAML files to define the laboratory configuration and performs operations such as creating, editing, verifying, or deleting virtual machines (VMs) in the lab.

Key functionalities:
1. Parses command-line arguments to configure the program's behavior.
2. Reads a YAML file that defines the virtual lab's structure, including VM prototypes, resource pools, and IP configurations.
3. Connects to a cluster of ESX servers to manage VMs and resources.
4. Verifies the existence of VM prototypes, resource pools, and paths on the servers.
5. Checks and allocates IP addresses for the lab using an IPAM (IP Address Management) service.
6. Handles errors and warnings during the process, ensuring the lab is set up correctly.

The script is modular, with functions for specific tasks like reading the lab file, checking prototypes, verifying resource pools, creating paths, and managing IP addresses.
"""

# Initialize logger before importing myESX modules
import logging, sys, os

from typing import Optional, Sequence, Dict

class Mylogging:
    NORMAL = int((logging.WARNING+logging.INFO)/2)
    VERBOSE = int((logging.INFO+logging.DEBUG)/2)
    DEVELOP = int((logging.DEBUG+logging.NOTSET)/2)

    def __init__(self, format:str='short'):
        self.mylogger = logging.getLogger()
        if format == 'long':
                logging.basicConfig(format='%(asctime)s:%(name)s:%(filename)s(line %(lineno)d)/%(funcName)s:%(levelname)s:%(message)s',stream=sys.stderr, level=logging.DEBUG)
        if format == 'short':
                logging.basicConfig(format='%(asctime)s:%(filename)s(line %(lineno)d):%(levelname)s:%(message)s',stream=sys.stderr, level=logging.DEBUG)
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



#mylogger = logging.getLogger()
#logging.basicConfig(format='%(asctime)s:%(name)s:%(filename)s(line %(lineno)d)/%(funcName)s:%(levelname)s:%(message)s',stream=sys.stderr, level=logging.DEBUG)
#logging.basicConfig(format='%(module)s/%(funcName)s(%(lineno)03d):%(levelname)s:%(message)s',stream=sys.stderr, level=logging.WARNING)

mylogger = Mylogging()

try:
    from phpypamobjects import ipamServer, ipamAddress, ipamSubnet, ipamScanAgent
except ImportError as e:
    sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
    from phpypamobjects.phpypamobjects import ipamServer, ipamAddress, ipamSubnet, ipamScanAgent
from ipaddress import ip_address, ip_network

import argparse
import re
import signal
import time
from datetime import datetime, timedelta, timezone
import textwrap
try:
    import nmap
except Exception as e:
    mylogger.critical(f"{str(e)}")
    mylogger.critical(f"Install modules: python-nmap \n\twith 'pip3 install <module1> <module2> ...'")
    sys.exit(1)

# Default interval between scans in seconds
default_poll_interval:int = 60 * 10 # 10 minutes
default_rescan_interval:int = 60 * 15 # 15 minutes
default_discovery_interval:int = 60 * 60 * 4 # 4 hours
default_nmap_Options:Dict[str,Dict[str,str]] = {
    'rescan': {
        '4': '-sn',
        '6': "-6 --script=targets-ipv6-multicast-echo.nse --script-args 'newtargets'"
        },
    'discover': {
        '4': "-sS -PS",
        '6': "-6  --script=targets-ipv6-multicast-echo.nse --script-args 'newtargets' -PN"
        }
    }

# Parameters of the program
class Parameters(argparse.Namespace):
    """Custom Parameters"""
    def __init__(self):
        super().__init__()
        
        self.progname:str = os.path.basename(sys.argv[0])
        self.debug = 0
        self.quiet:bool = False
        self.rescan_interval:timedelta = timedelta(seconds=float( os.getenv("SCANAGENT_RESCAN_INTERVAL", default_rescan_interval) ))
        self.discovery_interval:timedelta = timedelta(seconds=float( os.getenv("SCANAGENT_DISCOVERY_INTERVAL", default_discovery_interval) ))
        self.poll_interval:timedelta = timedelta(seconds=float( os.getenv("SCANAGENT_POLL_INTERVAL", default_poll_interval) ))
        
        self.nmap_Options:Dict[str,Dict[str,str]] = {
            'rescan': {
                '4': os.getenv("SCANAGENT_NMAP_RESCAN_IPV4OPTIONS",default_nmap_Options['rescan']['4']),
                '6': os.getenv("SCANAGENT_NMAP_RESCAN_IPV6OPTIONS",default_nmap_Options['rescan']['6'])
            },
            'discover': {
                '4': os.getenv("SCANAGENT_NMAP_DISCOVER_IPV4OPTIONS",default_nmap_Options['discover']['4']),
                '6': os.getenv("SCANAGENT_NMAP_DISCOVER_IPV6OPTIONS",default_nmap_Options['discover']['6'])
            }
        }

        self.agentCode = os.getenv("SCANAGENT_CODE",'')
        path:str = os.getenv("HOME",".")
        self.immediateDiscovery:bool = False
        self.immediateRescan:bool = False
        self.osmatch:bool = False
        if os.getenv("SCANAGENT_OSDETECT"):
            self.osmatch = True

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
    def __init__(self, helpIndent:int=2):
        """Initialize the command line parser."""
        self.wrapper = textwrap.TextWrapper(
            width=self.get_terminal_width(70),
            initial_indent=' ' * helpIndent,
            subsequent_indent=' ' * helpIndent,
            break_long_words=True,
            break_on_hyphens=True,

        )
        self.description=textwrap.dedent('''\
            This program is a scanning agent for phpIPAM service.

            The puropose of this program is running continuously as a service to detect new and active hosts in a set of IP networks and register them at a phpIPAM service. The agent uses the NMAP tool to perform efficient scans. NMAP must be installed in the system to perform the scans.

            IPAM service connection parameters, and scan related parameters can be configured with environment variables which are overrident by command line arguments.
                                                                                                                            
            The target IP subnets to be scanned are obtained from the phpIPAM service through its RESTful API. The agent code provided in the configuration is used to determine its identity and select the proper set of subnets to scan. The agent performs periodic discovery scans (slow) and update rescans (fast) at the intervals marked by the local configuration parameters (discovery and rescan intervals).
                                                     
            After scanning each subneet, the agent stores persistently the last discovery and last rescan timestamps at the IPAM service. New scans are started only after the corresponding intervals have elapsed even when restarting the agent.
            
            Discovered hosts are registered at the IPAM service in the corresponding subnet and entries are populated with as much data as possible, including DNS hostname, MAC address and some open TCP ports.
                                         
            During rescan updates, the agent only pings already existing hosts to update the last seen timestamp. No new hosts are added during rescan passes.''')
        self.cmdline_parser:argparse.ArgumentParser
        self.parser_vm:argparse.ArgumentParser
        self.init_cmdline_parser()
 
    def get_terminal_width(self, default=80):
        try:
            return os.get_terminal_size().columns
        except (AttributeError, OSError):
            mylogger.warning('Could not read terminal width for help formatter.')
            return default
        
    def mywrap(self, par):
        indent = 0
        w = self.get_terminal_width()+indent
        if par:
            return [textwrap.fill(line, width=w, initial_indent=' '*indent) for line in textwrap.wrap(par,width=w,initial_indent=' '*indent)]
        else:
            return ['']

    def myformat(self, text):
        return '\n'.join([line for par in text.split('\n') for line in self.mywrap(par)])

    def mystr2intervalConvert(self, intervalStr:str) -> timedelta:
        return timedelta(seconds=float(intervalStr))

    class DictAction(argparse.Action):
        def __init__(self, option_strings, dest, nested_key, **kwargs):
            self.nested_key = nested_key
            super().__init__(option_strings, dest, **kwargs)
        
        def __call__(self, parser, namespace, values, option_string=None):
            if not hasattr(namespace, self.dest):
                setattr(namespace, self.dest, {})
            
            target_dict = getattr(namespace, self.dest)
            keys = self.nested_key.split('.')
            current = target_dict
            
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            current[keys[-1]] = values


    def init_cmdline_parser(self):
        """Initialize the command line parser."""
        self.cmdline_parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            #formatter_class=lambda prog: argparse.ArgumentDefaultsHelpFormatter(prog,width=self.get_terminal_width()),
            #formatter_class=lambda prog: self.SmartFormatter(prog, width=self.get_terminal_width()),
            description = self.myformat(self.description)
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

        # Discover OS type
        self.cmdline_parser.add_argument('-o', action='store_true', dest='osmatch', help='Detect also OS type during network discovery. Needs root user in POSIX systems.')
        # Scan intervals
        self.cmdline_parser.add_argument('-r', metavar='interval', dest='rescan_interval', type=self.mystr2intervalConvert, help='Interval between network rescans (in seconds).')
        self.cmdline_parser.add_argument('-d', metavar='interval', dest='discovery_interval', type=self.mystr2intervalConvert, help='Interval between network discoveries (in seconds).')
        self.cmdline_parser.add_argument('-p', metavar='interval', dest='poll_interval', type=self.mystr2intervalConvert, help='Interval between agent polls of IPAM subnets (in seconds).')
        self.cmdline_parser.add_argument('-fR', action='store_true', dest='immediateRescan', help='Force immediate rescan when starting agent without completing the rescan interval.')
        self.cmdline_parser.add_argument('-fD', action='store_true', dest='immediateDiscovery', help='Force immediate discovery when starting agent without completing the discovery interval.')
        # Agent identity
        self.cmdline_parser.add_argument('-a', metavar='agentCode', dest='agentCode', type=str, required=False, help='Code to identify this scan agent.')

        # NMAP options
        self.cmdline_parser.add_argument('--nm-r4-opts', metavar='nmap_cmd_options', dest="nmap_Options", nested_key='rescan.4', action=self.DictAction, help='A string with options to launch nmap command when rescanning IPv4 subnets.')
        self.cmdline_parser.add_argument('--nm-r6-opts', metavar='nmap_cmd_options', dest="nmap_Options", nested_key='rescan.6', action=self.DictAction, help='A string with options to launch nmap command when rescanning IPv6 subnets.')
        self.cmdline_parser.add_argument('--nm-d4-opts', metavar='nmap_cmd_options', dest="nmap_Options", nested_key='discover.4', action=self.DictAction, help='A string with options to launch nmap command when discovering IPv4 subnets.')
        self.cmdline_parser.add_argument('--nm-d6-opts', metavar='nmap_cmd_options', dest="nmap_Options", nested_key='discover.6', action=self.DictAction, help='A string with options to launch nmap command when discovering IPv6 subnets.')

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

def actionOnSubnet(subnet:ipamSubnet, currentAgent:int) -> Optional[str]:
    # Skip subnets not assigned to this agent
    if subnet.getscanAgent() != currentAgent:
        mylogger.debug(f"Subnet not ours: {subnet.getSubnet()} ({subnet.getDescription()}) agent={subnet.getscanAgent()}")
        return 'skip'

    # Skip subnets which are not pools
    if subnet.getisPool() == 0:
        mylogger.debug(f"Subnet not a pool: {subnet.getSubnet()} ({subnet.getDescription()})")
        return 'skip'

    # Discover subnet if enabled and if last discovery is older than the discovery interval
    lastDiscover = subnet.getLastDiscovery()
    if subnet.getdiscoverSubnet() == 1:
        if parameters.immediateDiscovery or datetime.now(tz=lastDiscover.tzinfo) > (lastDiscover + parameters.discovery_interval):
            return 'discover'
    
    # Rescan subnet if enabled and if last rescan is older than the rescan interval
    lastRescan = subnet.getLastRescan()
    if subnet.getpingSubnet() == 1:
        if parameters.immediateRescan or datetime.now(tz=lastRescan.tzinfo) > (lastRescan + parameters.rescan_interval):
            return 'rescan'

###################################################################
# Scanning functions
###################################################################    

def create_ipaddresses(ipam:ipamServer, subnet:ipamSubnet, nm:nmap.PortScanner, hostsToCreate:Sequence[ipamAddress], osmatch:bool = False):
    # For each new host create fields
    erroneous:Sequence[ipamAddress] = []
    for ipam_host in hostsToCreate:
        try:
            nm_host = nm[str(ipam_host.getIP())]
            # Add hostname
            if nm_host.hostname():
                ipam_host.setHostname(nm_host.hostname())
            ipam_host.setAgentId(agent.getId()) # type: ignore
            ipam_host.updateScanFirstDate()

            # Add timestamp
            ipam_host.updateLastSeen()

            # Add list of TCP ports
            if nm_host.all_tcp():
                ipam_host.setTCPports(
                    ', '.join([f"{p}({nm_host.tcp(p)['name']})" for p in nm_host.all_tcp() if nm_host.tcp(p)['state']=='open'])
                    )
                
                # Try to detect if current OS is Windows or Linux
                # UNIX/Linux runs not RDP
                if 3389 in nm_host.all_tcp() and nm_host.tcp(3389)['state']=='closed':
                    ipam_host.setCurrentOS('U')
                # Windows runs RDP
                if 3389 in nm_host.all_tcp() and re.match(r'open.*',nm_host.tcp(3389)['state']):
                    ipam_host.setCurrentOS('W')
                
            # Add MAC if present
            nm_addresses:Dict[str,str] = nm_host.get('addresses',{'mac': ''})
            nm_mac = nm_addresses.get('mac')
            if nm_mac:
                ipam_host.setMAC(nm_mac)

            # Add OS info if present
            nm_osmatchInfo = nm_host.get('osmatch','')
            if nm_osmatchInfo:
                osname = nm_osmatchInfo[0]['name']
                if osname:
                    ipam_host.setDetectedOS(osname)
        except PermissionError as e:
            mylogger.error(f'Error setting fields for new address {ipam_host.getIP()}: {e}')
        else:
            # Create new IP in IPAM
            try:
                ipam.registerIP(ipam_host)
                mylogger.normal(f"NEW HOST {ipam_host}")
            except Exception as e:
                mylogger.error(f'Error adding host {ipam_host}: {str(e)}')
                mylogger.debug(f"Failed creation request: {ipam_host.getDictionary()}")
                erroneous.append(ipam_host)
    mylogger.verbose(f'Created: {len(hostsToCreate)-len(erroneous)} IPs/Failed to create {len(erroneous)} IPs.')

    # Update network discovery timestamp
    ipam.updateSubnetLastDiscovery(subnet)

def update_ipaddresses(ipam:ipamServer, subnet:ipamSubnet, nm:nmap.PortScanner, hostsToUpdate:Sequence[ipamAddress], osmatch:bool = False):
    # For each existing host update some fields
    for ipam_host in hostsToUpdate:
            nm_host = nm[str(ipam_host.getIP())]
            # Update hostname
            if nm_host.hostname():
                try:
                    ipam_host.setHostname(nm_host.hostname())
                except PermissionError as e:
                    mylogger.error(f'Error updating field hostname for address {str(ipam_host.getIP())}: {e}')

            # Update timestamp
            try:
                ipam_host.updateLastSeen()
            except PermissionError as e:
                mylogger.error(f'Error updating field lastseen for address {str(ipam_host.getIP())}: {e}')

            # Update list of TCP ports if available
            if nm_host.all_tcp():
                try:
                    ipam_host.setTCPports(
                        ', '.join([f"{p}({nm_host.tcp(p)['name']})" for p in nm_host.all_tcp() if nm_host.tcp(p)['state']=='open']))
                except PermissionError as e:
                    mylogger.error(f'Error updating field tcpports for address {str(ipam_host.getIP())}: {e}')

                
                # Try to detect if current OS is Windows or Linux
                # UNIX/Linux runs ssh and not RDP
                if 3389 in nm_host.all_tcp() and nm_host.tcp(3389)['state']=='closed':
                    try:
                        ipam_host.setCurrentOS('U')
                    except PermissionError as e:
                        mylogger.error(f'Error updating field currentOS for address {str(ipam_host.getIP())}: {e}')

                # Windows runs netbios and RDP
                if 3389 in nm_host.all_tcp() and nm_host.tcp(3389)['state']!='closed':
                    try:
                        ipam_host.setCurrentOS('W')
                    except PermissionError as e:
                        mylogger.error(f'Error updating field currentOS for address {str(ipam_host.getIP())}: {e}')

            # Update MAC if present
            nm_addresses:Dict[str,str] = nm_host.get('addresses',{'mac': ''})
            nm_mac = nm_addresses.get('mac')
            if nm_mac:
                try:
                    ipam_host.setMAC(nm_mac)
                except PermissionError as e:
                    mylogger.error(f'Error updating field mac for address {str(ipam_host.getIP())}: {e}')

            # Add OS info if present and description is not set
            osmatchInfo = nm_host.get('osmatch','')
            if osmatchInfo:
                osname = osmatchInfo[0]['name']
                if osname:
                    try:
                        ipam_host.setDetectedOS(osname)
                    except PermissionError as e:
                        mylogger.error(f'Error updating field detectedOS for address {str(ipam_host.getIP())}: {e}')

            # Update IP in IPAM
            try:
                ipam.updateAddress(ipam_host)
            except Exception as e:
                mylogger.error(f'Error updating host in ipam service: {str(e)}')
            mylogger.verbose(f"UPDATE HOST {ipam_host}")
    # Update network rescan timestamp
    ipam.updateSubnetLastScan(subnet)

def discover_subnet(ipam:ipamServer, subnet:ipamSubnet, ports:str="22,53,67,69,80,111,139,443,3389,3306,5432,8000,9000", osmatch:bool = False):
    """
    Scan a subnet for hosts responding to ICMP ping (host discovery).
    
    :param subnet: Subnet to scan.
    :return: (List of IP addresses to update,List of IP addresses to create)
    """
    mylogger.verbose(f"Discovering subnet: {subnet.getSubnet()}")
    # Get existing IPs from IPAM
    existingHosts:Sequence[ipamAddress] = ipam.findIPsbyNet(subnet)                        
    mylogger.debug(f'Existing hosts: {len(existingHosts)}')

    # Get DNS servers for this subnet
    dnsservers = ','.join([str(dns) for dns in ipam.dns_subnet(subnet)])
    if dnsservers:
        dnsserversOptions = f"-R --dns-servers {dnsservers}"
    else:
        dnsserversOptions = ''

    nm = nmap.PortScanner()
    osmatchOptions = ''
    # Detect OS and  if running as root in POSIX systems to OS detection
    if osmatch:
        if (os.name == 'posix' and os.getuid() == 0 ) or os.name == 'nt':
            osmatchOptions = '-O'
    nmaparguments = f"{parameters.nmap_Options['discover'][str(subnet.getSubnet().version)]} {dnsserversOptions} {osmatchOptions}"
    mylogger.verbose(f"Launching nmap for discovery with arguments='{nmaparguments}'")

    # Launch nmap process
    mylogger.develop(f'Starting nmap for subnet {str(subnet)}')
    if subnet.getSubnet().version == 4:
        nm.scan(hosts=str(subnet.getSubnet()), ports=ports, arguments=nmaparguments)
    if subnet.getSubnet().version == 6:
        nm.scan(ports=ports, arguments=nmaparguments)
    # Perform a ping scan (no port scan, just host discovery)
    #nm.scan(hosts=str(subnet.getSubnet()), arguments='-sn')
    mylogger.develop(f'Ending nmap for subnet {str(subnet)}: status={nm.scanstats} cmd={nm.command_line}')

    # Filter active hosts
    activeHosts = [ip_address(host) for host in nm.all_hosts() if nm[host].state() == 'up']
    mylogger.debug(f'Active Hosts for subnet {str(subnet)}: {len(activeHosts)}')

    # Filter active hosts belonging to this subnet (IPv6 scan reports IPv6 addresses for all interfaces and also local-link addresses)
    thisSubnetHosts = [host for host in activeHosts if host in subnet.getSubnet()]

    # Get existing IPs seen active right now (ipam hosts in nmap hosts belonging to this subnet)
    hostsToUpdate = [ipamAddr for ipamAddr in existingHosts if ipamAddr.getIP() in thisSubnetHosts]
    mylogger.debug(f'Hosts to update for subnet {str(subnet)}: {len(hostsToUpdate)}')
    # Update in IPAM
    update_ipaddresses(ipam=ipam, subnet=subnet, nm=nm, hostsToUpdate=hostsToUpdate, osmatch=osmatch)

    # Get new IPs seen active right now (nmap hosts not in existing ipam)
    hostsToCreate = [ipamAddress(ip=newhost, subnet=subnet) for newhost in thisSubnetHosts if newhost not in [hostToUpdate.getIP() for hostToUpdate in hostsToUpdate]]
    mylogger.debug(f'Hosts to create for subnet {str(subnet)}: {len(hostsToUpdate)}')
    # Update in IPAM
    create_ipaddresses(ipam=ipam, subnet=subnet, nm=nm, hostsToCreate=hostsToCreate, osmatch=osmatch)

def rescan_subnet(ipam:ipamServer, subnet:ipamSubnet, ports:str="22,139,3389"):
    """
    Ping a subnet for hosts responding to ICMP ping (host ping).
    This function aggregates existing IPs in subnets /24 to avoid pinging whole subnets in masks smaller than /24.
    
    :param subnet: Subnet to scan.
    :return: (List of IP addresses to update,List of IP addresses to create)
    """
    mylogger.verbose(f"Rescanning subnet: {subnet.getSubnet()} ({subnet.getDescription()})")
    # Get existing IPs from IPAM
    existingHosts = ipam.findIPsbyNet(subnet)                        
    mylogger.debug(f'Existing hosts: {len(existingHosts)}')

    # Get DNS servers for this subnet
    dnsservers = ','.join([str(dns) for dns in ipam.dns_subnet(subnet)])
    if dnsservers:
        dnsserversOption = f"-R --dns-servers {dnsservers}"
    else:
        dnsserversOption = ''
    nm = nmap.PortScanner()
    nmaparguments = f"{parameters.nmap_Options['rescan'][str(subnet.getSubnet().version)]} {dnsserversOption}"
    mylogger.verbose(f"Launching nmap for rescan with arguments='{nmaparguments}'")

    # Prepare list of networks to ping rounding IPs up to networks of size /24
    if subnet.getSubnet().prefixlen < 24:
        networksToPing = sorted(list(set( [ip_network(ip.getIP(),strict=False).supernet(new_prefix=24) for ip in existingHosts] )))
    else:
        networksToPing = [subnet.getSubnet()]

    if subnet.getSubnet().version == 4:
        # Scan subnetworks with some address
        for pingnet in networksToPing:
            mylogger.develop(f'Starting nmap for subnet {str(pingnet)}')
            #nm.scan(hosts=str(pingnet), ports=ports, arguments=nmaparguments)
            # Perform a ping scan (no port scan, just host discovery)
            nm.scan(hosts=str(pingnet), arguments=nmaparguments)
            mylogger.develop(f'Ending nmap for subnet {str(pingnet)}: status={nm.scanstats} cmd={nm.command_line}')

            # Filter active hosts
            activeHosts = [ip_address(host) for host in nm.all_hosts() if nm[host].state() == 'up']
            mylogger.debug(f'Active Hosts for subnet {str(pingnet)}: {len(activeHosts)}')

            # Filter active hosts belonging to this subnet (IPv6 scan reports IPv6 addresses for all interfaces and also local-link addresses)
            thisSubnetHosts = [host for host in activeHosts if host in subnet.getSubnet()]

            # Get existing IPs seen active right now (ipam hosts in nmap hosts)
            hostsToUpdate = [ipamAddr for ipamAddr in existingHosts if ipamAddr.getIP() in thisSubnetHosts]
            mylogger.debug(f'Hosts to update for subnet {str(pingnet)}: {len(hostsToUpdate)}')
            # Update in IPAM
            update_ipaddresses(ipam=ipam, subnet=subnet, nm=nm, hostsToUpdate=hostsToUpdate)
    if subnet.getSubnet().version == 6:
        mylogger.develop(f'Starting nmap for subnet {str(subnet.getSubnet())}')
        #nm.scan(hosts=str(pingnet), ports=ports, arguments=nmaparguments)
        # Perform a ping scan (no port scan, just host discovery)
        nm.scan(arguments=nmaparguments)
        mylogger.develop(f'Ending nmap for subnet {str(subnet.getSubnet())}: status={nm.scanstats} cmd={nm.command_line}')

        # Filter active hosts
        activeHosts = [ip_address(host) for host in nm.all_hosts() if nm[host].state() == 'up']
        mylogger.debug(f'Active Hosts for subnet {str(subnet.getSubnet())}: {len(activeHosts)}')

        # Filter active hosts belonging to this subnet (IPv6 scan reports IPv6 addresses for all interfaces and also local-link addresses)
        thisSubnetHosts = [host for host in activeHosts if host in subnet.getSubnet()]

        # Get existing IPs seen active right now (ipam hosts in nmap hosts)
        hostsToUpdate = [ipamAddr for ipamAddr in existingHosts if ipamAddr.getIP() in thisSubnetHosts]
        mylogger.debug(f'Hosts to update for subnet {str(subnet.getSubnet())}: {len(hostsToUpdate)}')
        # Update in IPAM
        update_ipaddresses(ipam=ipam, subnet=subnet, nm=nm, hostsToUpdate=hostsToUpdate)

###################################################################
# Signals handler
###################################################################    
class GracefulEndException(Exception):
    """Ending program with a message."""
    def __init__(self, signum, message="Graceful termination invoked", log = False):
        self.message = message
        super().__init__(self.message)
        if log:
            mylogger.error(message)

class CancelPauseException(Exception):
    """Ending pause """
    def __init__(self, signum, message="Cancel pause invoked", log = False):
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
        if os.name == 'posix':
            signal.signal(signal.SIGUSR1, self.cancel_pause)
            signal.signal(signal.SIGUSR2, self.cancel_pause)

    def exit_gracefully(self, signum, frame):
        self.kill_now = True
        if self.interrupt_me:
            raise GracefulEndException(signum=signum, message=f"{signum}")

    def cancel_pause(self, signum, frame):
        if self.interrupt_me:
            raise CancelPauseException(signum=signum, message=f"{signum}")

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
    global agent
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
    # Detect OS and  if running as root in POSIX systems to OS detection
    if parameters.osmatch:
        if (os.name == 'posix' and os.getuid() != 0 ):
            mylogger.error("OS detection requires root privileges. Run with sudo.")
            sys.exit(1)

    if parameters.discovery_interval.seconds < 60 or parameters.rescan_interval.seconds < 60 or parameters.poll_interval.seconds < 60:
        mylogger.error("Intervals can not be less than one minute.")
        sys.exit(1)

    


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

        mylogger.normal(f"Starting scanning agent {agent.getName()} ({agent.getType()}): {agent.getDescription()}")

        ##################################################################
        # Scan loop
        ##################################################################
        while not sighandler.kill_now:
            # Get the timestam for the last time the agent started scans on this IPAM service
            tsStartScan = agent.getLastAccess()
            # If never polled, assume a past poll
            if not tsStartScan:
                tsStartScan = datetime.now() - parameters.poll_interval
            # Get current time
            tsNow = datetime.now()
            # Compute how much time to sleep to be periodic
            tsNextScan = tsStartScan + parameters.poll_interval
            pause = tsNextScan.timestamp() - tsNow.timestamp()
            

            # If force flag was set at start don't sleep for the first time
            if pause >0 and not parameters.immediateDiscovery and not parameters.immediateRescan:
                try:
                    # Sleep for remaining time
                    mylogger.verbose(f'Scan agent last poll at {tsStartScan.isoformat()}. Now is {tsNow.isoformat()}. Remaining pause of {pause} seconds of poll interval of {parameters.poll_interval.seconds}.')
                    time.sleep(pause)
                    mylogger.verbose(f'Scan agent waking up')
                except CancelPauseException as e:
                    mylogger.warning(f"Pause canceled with signal {e.message}")

            else:
                mylogger.verbose(f'Scan agent last poll at {tsStartScan.isoformat()}. Now is {tsNow.isoformat()}. Skipping pause of {pause} seconds.')

            # Check gracefull end request if exceptions are disabled
            if sighandler.kill_now:
                break
            
            try:
                # Update scan agent timestamp at IPAM with time when starting all scans
                ipam.updateScanAgent(agent)

                # Read all ranges from IPAM
                mylogger.verbose(f"Reading subnets from IPAM server.")
                subnets = ipam.getAllSubnets()
                if not subnets:
                    mylogger.warning("No subnets found in IPAM")
                else:
                    for subnet in subnets:
                        action:Optional[str] = actionOnSubnet(subnet, agent.getId())
                        if action == 'skip':
                            pass
                        if action == 'discover':
                            # Scan subnet with NMAP
                            discover_subnet(ipam, subnet=subnet, osmatch=parameters.osmatch)
                        if action == 'rescan':
                            # Scan subnet with NMAP
                            rescan_subnet(ipam, subnet=subnet)

                        # Check gracefull end request if exceptions are disabled
                        if sighandler.kill_now:
                            break
                
            except Exception as e:
                mylogger.critical(f"Exception {e}")

            # If force was specified, reset it to avoid skipping
            parameters.immediateDiscovery = False
            parameters.immediateRescan = False

    ##################################################################
    # Daemon end requested
    ##################################################################
    except GracefulEndException as e:
        mylogger.warning(f"Daemon interrupted by exception {e.message}")

    mylogger.normal(f"{parameters.progname}: Ending")

if __name__ == "__main__":
    main()
