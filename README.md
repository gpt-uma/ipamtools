# IPAMTOOLS

A set of command line tools that interact with to phpIPAM service

## Description

This project provides some tools that help interacting with the IPAM server from command line. Current tools include:
- `ipamScanAgent`: A scanning agent able to connect to phpIPAM service and scan a set of networks assigned to it. Address scanning is implemented using the nmap tool.
- `ipam2text`: A client to dump as a plain text list the whole list of subnets and addresses of a phpIPAM service.

### Requirements
- **Python 3.9.2** or higher (it uses python typing features)
- **setuptools** library.

### Installation

**ipamtools** is distributed as a standard Python project. It is installed with `pip` in the same way as a standard Python package.

```bash
pip install ipamtools
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

Options describing the parameters to connect to the **phpIPAM** service:
  * `--ipam-url url`:       URL of the IPAM service.
  * `--ipam-appid appid`:   Application ID for the IPAM service.
  * `--ipam-token token`:   Application access token for the IPAM service.
  * `--ipam-user user`:     Username for the IPAM service.
  * `--ipam-ca ca`:         URL or Filename of a PEM file containing the public Certificate of the CA signing the server certificates of IPAM service.

Options controlling debugging levels:
  * `-v`: Increment detail of debugging messages. Each ocurrence increments one level the debugging level.
  * `-q`: Decrement detail of debugging messages. Each occurrence decrements the debugging level.

  Available debugging levels are: DEVELOP, DEBUG, VERBOSE, NORMAL, WARNING, ERROR, CRITICAL. The default level at start is NORMAL.

## Preparing the API connection of the client to phpIPAM
Before executing the tools, you have to setup the connection parameters for clients in the **phpIPAM server** as `admin` user:
1.  In the `Administration/API` section, create a new App ID and App Code to allow
    the access for scan agents. Several scan agents can use the same App ID and
    App Code, or share the same.
    - `App permissions`: Set it to 'Read/Write'.
    - `App security`: set it to 'User Token' by now.
 1. In the `Administration/Groups` section, create a new group for scan agents.
 1. In the `Administation/Sections` section, create edit all sections ad add rw
    permissions for the new group for scan agents.
 1. In the `Administration/Users` section, create one or more users for your scan agents.
    Agents can use the same user or different users. Add users to the new group
    for scan agents.
    - `User role`: set it to normal user.
    - `Authentication method`: set it to local.


## Scan Agent (ipamScanAgent)

### Description

`ipamScanAgent` is a address scanner agent specific for the **phpIPAM** service.
*  It is based on the `nmap` application to do the grind work of implementing different methods of scanning IP addresses and TCP/UDP ports. It should be installed alongside `nmap`.
* It also uses the `phpIPAM service API` to retrieve the list of subnets which are *assigned* to this agent and to create newly discovered addresses and to update existing ones when they answer to subsequent scans.

 The agent is intended to be installed and run in several strategic hosts at your company's network that have *better* visibility of some subnets which might be *hidden* from the network point of view of the phpIPAM server. Its mission is to watch a subset of the subnets (IP ranges) defined at phpIPAM performing two tasks on them:
* Discovery: This task implies detecting new addresses which have never been observed before. The agent uses nmap to scan the subnet and also a limited list of open TCP ports. The list can be redefined, but as the list length increases, the discovery process becomes slower. Addresses of not existing hosts are created in phpIPAM. Existing hosts are also scanned for open TCP ports.  `nmap` is also used to guess the type of Operating System running on each IP address (this is not very precise, but it can add some approximate information). Both new and existing addresses are updated with the information obtained by nmap:
  * *hostname*: as resolved by DNS servers,
  * *MAC*: only if the scan agent executes on a host directly connected to the LAN of the subnet,
  * *list of open TCP ports*: restricted to the list of scanned ports.
  * *detected OS type*: only if nmap heuristics are able to guess it.
  * *last seen timestamp*: updated to the current time when the IP is updated.

* Rescan: This task implies scanning only existing address and update them if seen again. The type of scan is determined by the type of host detection used by nmap (*see below for options for changing nmap behaviour*). Only *MAC*, *hostname* and the *last seen timestamp* fields are updated.

### Configuration and timing of discoveries and rescans

The configuration of the agent is split between local parameters specified by command line options (or *environment variables*) and scan configuration stored at the *phpIPAM* service:
* Local parameters specify the intervals between subsequent discoveries and between subsequent rescans. The intervals are the same for all subnets, but each instance of the agent can be given its own intervals when launched (different agents could be run at the same host for different networks).
* Remote scanning information is specified at the phpIPAM service for each subnet. The desired scan agent can be selected for each subnet, and rescan and discovery can be enabled individually.

Each `ipamscanagent` should run forever as a service on its host. The agent sleeps and wakes up only for discovery and rescan tasks:
* It wakes up every `pause interval` (specified by the `-p` option). At every wakeup, it recovers the list of subnets assigned to this agent from the *phpIPAM service*.
* For each subnet it reads the *last scan* and *last discovery* timestamps, and computes if the `discovery period` or the `rescan period` has expired. If so, it launches the corresponding task. The discovery task is prefered over the rescan task if both intervals have been exceeded. After the task is ended, the corresponding timestamp is updated in the phpIPAM service.
* When all subnets have been processed, the agent calculates how long it has to sleep until the next wakeup considering the time employed in all tasks since it woke up. This is done to keep wakeup times as periodic as possible. If the agent is restarted, it will remember the last time that it performed scans and discoveries and will sleep for a shorter time or scan immediately if the pause interval has expired.
* If the agent is launched with the *force rescan* or *force discovery* options, it will ignore the *pause interval* and also the corresponding *rescan* or *discovery* period of all subnets and will start the corresponding task immediately. This is useful to force a rescan or discovery of all subnets in case of a network change or when the agent is started for the first time.

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
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Contact
Guillermo Pérez Trabado, University of Málaga, Spain.

For any questions or issues, please contact the author at [guille@ac.uma.es](mailto:guille@ac.uma.es).
