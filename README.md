# PHPYPAMOBJECTS

A high level API client library for phpIPAM written in Python.

## Description
This library is a wrapper around the phpypam library, which is a Python client for the phpIPAM API. It provides a higher-level interface to interact with phpIPAM, making it easier to work with IP address management tasks.
The library is designed to simplify the process of managing IP addresses, subnets, and other related tasks in phpIPAM. It provides a set of classes and methods that abstract away the complexities of the underlying API, allowing developers to focus on their specific use cases.
The library includes features such as:
- Simplified connection to a phpIPAM service.
- Simplified methods for creating, retrieving, and updating IP addresses, subnets and other objects from phpIPAM.
- Simple object-oriented interface with methods for common tasks on IP addresses and subnets.
- Support for retrieval of IP addresses and networks from phpIPAM service, such as searching by IP address, subnet, hostname or subnet address range.
- Support for IPv4 and IPv6 addresses.
- Handling and logging of errors and exceptions.
- Support for timestamping of changes for subnets and addresses.
- Support for allocation of free IP addresses from subnets selecting algorithms managing fragmentation of ranges of free addresses (best-fit, first-fit, and worst-fit).
- Implements some form of protection against the scanning agent updating or deleting some special addresses (base address, broadcast address, router address) in subnets.

## Requirements
- Python 3.12 or higher (it uses python typing features)
- phpypam library
## Installation

```bash
pip install phpypamobjects
```
## Usage

```python

from phpypamobjects import ipamServer
# This is not needed, but maybe you want to do IP address manipulation
from ipaddress import ip_address, IPv4Address, IPv6Address
# Just for pattern matching names in the example
import re

# Connect the service
ipam = ipamServer(
    url='https://myphpipam.example.com',
    app_id='myipamclient',
    token='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    user='myipamuser',
    password='ppppppppppppppppppppp'
)

# Get all subnets
subnets=ipam.getAllSubnets()
for sn in subnets:
    # Print subnet description
    print(f'{sn} -- last scanned at: {sn.getLastRescan()} -- last discovered at: {sn.getLastDiscovery()}')
    # Reserve and annotate unusable IPs of this subnet (baseaddress, broadcast, router)
    ipam.annotate_subnet(sn, hasRouter=True, force=True)
    # Find all IPs of this subnet
    aList = ipam.findIPsbyNet(sn)
    
    # Print all IPs of this subnet
    for a in aList:
        # Print IP address description
        print(a)
        # Match some content in the IP description
        if re.match("test.*", a.getDescription()):
            # Modify some fields of the IP
            a.updateMac('00:00:00:00:00:00')
            a.updateField('description', 'test-update')
            a.updateLastSeen()
            # Update address at the phpIPAM service
            ipam.updateAddress(a)

            # Use the ip address for anything else
            call_some_function(str(ip.getIP()))

            # Some fancy operations using ipaddress library
            if ip.getIP() in sn.getSubnet():
                print(f'{ip} is in {sn}')
            else:
                print(f'{ip} is NOT in {sn}')

    # Get a list of 11 free addresses from this subnet using the best-fit algorithm
    free_ips = ipam.getFreeIP(sn, 11, fitAlg='BestFit')
    # Register returned addresses as used
    for ip in free_ips:
        ip.updateField('description', 'test-free')
        ip.updateField('hostname', 'test-new-host')
        # Register the IP address as used
        ipam.registerIP(ip)

```

Python comprension can be used or even abused to make more compact code:

```python
# Get only /24 subnets
subnets=[sn for sn in ipam.getAllSubnets() if sn.getMask() == '24']

# Get addresses from those subnets matching a pattern in the description
aList = [a for sn in subnets for a in ipam.findIPsbyNet(sn) if re.match(r"test.*", a.getDescription())]

# Get all subnets scanned by a Scanning Agent named 'agent1'
agent = [agent for agent in ipam.getAllScanAgents() if agent.getDescription() == 'agent1'].pop()
scannedSubnets = [sn for sn in ipam.getAllSubnets() if sn.scanAgent == agent.getId()]
for sn in scannedSubnets:
    # Print subnet description
    print(f'{sn} -- last scanned at: {sn.getLastRescan()} -- last discovered at: {sn.getLastDiscovery()}')

```    

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
Guillermo Pérez Trabado, University of Málaga, Spain.

For any questions or issues, please contact the author at [guille@ac.uma.es](mailto:guille@ac.uma.es).
