# IPAMTOOLS

A set of command line tools that interact with to phpIPAM service

## Description

This project provides some tools that help interacting with the IPAM server from command line. Current tools include:
- `ipamScanAgent`: A scanning agent able to connect to phpIPAM service and scan a set of networks assigned to it. Address scanning is implemented using the nmap tool.
- `ipam2text`: A client to dump as a plain text list the whole list of subnets and addresses of a phpIPAM service.

### Requirements
- `Python 3.7` or higher
- `phpypamobjects` python package
- `phpypam` python package
- `python-nmap` python package
- `nmap` tool installed

### Installation

`ipamtools` is distributed as a standard Python project. It is installed with `pip` in the same way as a standard Python package. `pip` will install all the python dependencies, but not the `nmap` tool.

```bash
pip install ipamtools
```

**Notice**: Currently this package is not part of python packages auto-downloaded by pip.  If pip does not install automatically the `ipamtools` package, you should install it manually specifying the URL of the package in the `dist` folder of the repository.

```bash
pip install https://github.com/gpt-uma/ipamtools/tree/main/dist/ipamtools-<version>.tar.gz
```


## Usage

As a native Python project, the installer generates a script as the entry point to each tool. The script directory is not included by default in the path. Its default location is *$HOME/.local/bin*. For example:
```bash
_$ $HOME/.local/bin/ipamscanagent -v -fD -fR

_$ $HOME/.local/bin/ipam2text -v
```

Tools can also be started as python modules:
```bash
_$ python3 -m ipamtools.ipamScanAgent -v -fD -fR

_$ python3 -m ipamtools.ipam2text -v
```

### Common options

These options describe authentication opetions to connect to the **phpIPAM** service:
  * `--ipam-url url`:       URL of the IPAM service.
  * `--ipam-appid appid`:   Application ID for the IPAM service.
  * `--ipam-token token`:   Application access token for the IPAM service.
  * `--ipam-user user`:     Username for the IPAM service.
  * `--ipam-ca ca`:         URL or Filename of a PEM file containing the public Certificate of the CA signing the server certificates of IPAM service, or NONE if you want to disable certificate validation (nor recommended in a production installation).

Options controlling debugging levels:
  * `-v`: Increment detail of debugging messages. Each ocurrence increments one level the debugging level.
  * `-q`: Decrement detail of debugging messages. Each occurrence decrements the debugging level.

  Available debugging levels are: DEVELOP, DEBUG, VERBOSE, NORMAL, WARNING, ERROR, CRITICAL. The default level at start is NORMAL.

## Preparing the API connection of the client to phpIPAM
Before executing these tools, you have to setup the connection parameters for clients in the **phpIPAM server** as `admin` user:
1.  In the `Administration/API` section, create a new App ID and App Code to allow access for a tool (e.g. scan agent). Several tools can use different App IDs and App Codes, or share the same. As scan agents need to start non-interactively, the connection credentials can be compromised. It is recommended to use individual credentials for agents executing on non trusted hosts, so that they can be revoked individually.
    - `App permissions`: Set them to 'Read/Write'.
    - `App security`: set it to 'User Token' by now.
 1. In the `Administration/Groups` section, create a new group for scan agents.
 1. In the `Administation/Sections` section, edit all sections ad add `rw` permissions for the new group for scan agents.
 1. In the `Administration/Users` section, create one or more users for your scan agents.
    Agents can share the same user or different users. Add users to the new group for scan agents.
    - `User role`: set it to normal user.
    - `Authentication method`: set it to local.

## Scan Agent tool (ipamScanAgent)

### Description

`ipamScanAgent` is a address scan agent specific for the **phpIPAM** service.
*  It is based on the `nmap` application to do the grind work of implementing different methods of scanning IP addresses and TCP/UDP ports. It should be installed alongside `nmap`.
* It also uses the `phpIPAM service API` to retrieve the list of subnets which are *assigned* to this agent and to create newly discovered addresses and to update existing ones when they answer to subsequent scans.

 The agent is intended to be installed and run in several *strategic* hosts at your company's network that have *visibility* of some subnets which might be *unreachable* from the phpIPAM server. Its mission is to watch over a set of the subnets (IP ranges) defined at phpIPAM performing these two tasks on them:
* Discovery: This task includes detecting new addresses which have never been seen alive before. The agent uses nmap to scan the subnet and also a limited list of open TCP ports. The list of ports can be redefined, but as the list of ports increases, the discovery process becomes slower. Addresses of not existing hosts are created in phpIPAM. Existing hosts are also scanned for open TCP ports.  `nmap` is also used to guess the type of Operating System running on each IP address (this is not very precise, but it can add some approximate information). Both new and existing addresses are updated with this information obtained by nmap. Some items are optional and can be left empty:
  * `hostname` (*optional*): as resolved by DNS servers,
  * `MAC` (*optional*): only if the scan agent executes on a host directly connected to the LAN of the subnet,
  * `list of open TCP ports` (*optional*): restricted to the list of scanned ports.
  * `detected OS type` (*optional*): only if nmap heuristics are able to guess it.
  * `last seen timestamp`: updated to the current time when the IP is updated.

* Rescan: This task implies scanning only existing address and update them if seen again. The type of scan is determined by the type of *host detection* used by nmap (*see below for options for changing nmap behaviour*). Only *MAC*, *open tcp ports* and the *last seen timestamp* fields are updated.

**Note 1**: The `phpypamobjects` library offers optional protection agains updating fields of addresses. If you want to protect one or several addresses against any update, set their `custom_apiblock` field to 1 in the database or use the `ipamService.annotate_address()` method. This prevents the scanner from changing any field.
**Note 2**: For addresses marked with tags different from `offline` and `used` or marked with the `is_gateway` field, only *MAC*, *open tcp ports* and the *last seen timestamp* can be updated.
**Note 3**: `nmap` provides very fast scanning methods based on broadcast and multicas if the host has an interface directly connected to the scanned subnet. This reduces scanning time from minutes to seconds for very large IP ranges.

### Configuration and timing of discoveries and rescans

The configuration of the agent is split between **local parameters** specified by command line options (or *environment variables*) and **scan configuration** stored at the *phpIPAM* service:
* Local parameters specify the intervals between subsequent discoveries and between subsequent rescans. The intervals are the same for all subnets, but each instance of the agent can be given its own intervals when launched (different agent instances could be run at the same host for different networks).
* Scanning information is defined at the phpIPAM service for each subnet. The desired scan agent can be selected for each subnet. Rescan and discovery for each individual subnet can be enabled or disabled at the phpIPAM service.

Each `ipamScanAgent` should run forever as a service on a host. The agent will sleep and wake up periodically  for discovery and rescan tasks:
* It wakes up every `pause interval` seconds (specified by the `-p` option). At every wakeup, it retrieves from the *phpIPAM service* the list of subnets assigned to this agent.
* For each subnet, it reads the *last scan* and *last discovery* timestamps, and computes if the `discovery period` or the `rescan period` have expired. If so, it launches the corresponding task. The discovery task is prefered over the rescan task if both intervals have been exceeded. After the task is ended, the corresponding timestamp is updated at the phpIPAM service.
* When all subnets have been processed, the agent calculates how long it has to sleep until the next wakeup considering the time employed in all tasks since it woke up. This is done to keep wakeup times as periodic as possible. If the agent is restarted, it will retrieve from the `phpIPAM service` the last time it woke up and will sleep for the remaining time or scan immediately if the pause interval has expired.
* If the agent is launched with the *force rescan* or *force discovery* options, it will ignore the *pause interval* and also the corresponding *rescan* or *discovery* period of all subnets and will start the mandated task immediately. This is useful to force starting an immediate rescan or discovery.

### Options

The options are:
  * `-a agentCode`:         Code to identify this scan agent.
  * `-o`:                   Detect OS type during network discovery. Needs to be executed as root user in POSIX systems.
                        systems.
  * `-p interval`:           Interval between agent polls of IPAM subnets (in seconds).
  * `-r interval`:           Interval between network rescans (in seconds).
  * `-d interval`:           Interval between network discoveries (in seconds).
  * `-fR`:                   Force immediate rescan. Skips the rescan interval only once at the beginning of execution of this agent.
  * `-fD`:                   Force immediate discovery. Skips the discovery interval only once at the beginning of execution of this agent.

The following options allow changing the default options of nmap for each case (rescan or discovery) for both IPv4 and IPv6 subnets. This allows fine control of the specific scanning method needed. The option string is a single string with all the options separated with spaces:
  * `--nm-r4-opts <nmap_cmd_options>`:
                        A string with options to launch nmap command when rescanning IPv4 subnets.
  * `--nm-r6-opts <nmap_cmd_options>`:
                        A string with options to launch nmap command when rescanning IPv6 subnets.
  * `--nm-d4-opts <nmap_cmd_options>`:
                        A string with options to launch nmap command when discovering IPv4 subnets.
  * `--nm-d6-opts <nmap_cmd_options>`:
                        A string with options to launch nmap command when discovering IPv6 subnets.

## Address dump to text (ipam2text)

### Description

The `ipam2text` command dumps to stdout each of the subnets existing in the phpIPAM service along with its list of IP addresses in a plain text format.

### Options

This command uses the common options described previously to connect to the phpIPAM service.

# License
This project is released under the GPL v3 License - see the [LICENSE] file for details.

# Contact
Guillermo Pérez Trabado, University of Málaga, Spain.

For any questions or issues, please contact the author at [guille@ac.uma.es](mailto:guille@ac.uma.es).
