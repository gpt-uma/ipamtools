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
_$ $HOME/.local/bin/ipam2text -v
_$ $HOME/.local/bin/ipamscanagent -v -fD -fR
```

Tools can also be started as python modules:
```bash
_$ python3 -m ipamtools.ipam2text -v
_$ python3 -m ipamtools.ipamScanAgent -v -fD -fR
```

### Common options

Options describing the parameters to connect to the **phpIPAM** service:
  * `--ipam-url url`:       URL of the IPAM service.
  * `--ipam-appid appid`:   Application ID for the IPAM service.
  * `--ipam-token token`:   Application access token for the IPAM service.
  * `--ipam-user user`:     Username for the IPAM service.
  * `--ipam-ca ca`:         URL or Filename of a PEM file containing the public Certificate of the CA signing the server certificates of IPAM service.

Options controlling debugging levels:
  * `-v`: Increment detail of debugging messages.
  * `-q`: Decrement detail of debugging messages.

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

What scan agent does.

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
  * `--nm-r4-opts nmap_cmd_options`:
                        A string with options to launch nmap command when rescanning IPv4 subnets.
  * `--nm-r6-opts nmap_cmd_options`:
                        A string with options to launch nmap command when rescanning IPv6 subnets.
  * `--nm-d4-opts nmap_cmd_options`:
                        A string with options to launch nmap command when discovering IPv4 subnets.
  * `--nm-d6-opts nmap_cmd_options`:
                        A string with options to launch nmap command when discovering IPv6 subnets.

## Address dump to text (ipam2text)

### Description


### Options


# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Contact
Guillermo Pérez Trabado, University of Málaga, Spain.

For any questions or issues, please contact the author at [guille@ac.uma.es](mailto:guille@ac.uma.es).
