
################################################################################
# This script should be sourced instead of executed if you want to
#   run your tests from the command line.
# You can also specify the parameters as command line options to the tools.
################################################################################


################################################################################
# Parameters to connect to the phpIPAM service
################################################################################

# Before running this script, go to phpIPAM server as admin user
#  -In the Administration/API section, create a new App ID and App Code to allow
#     the access for scan agents. Several scan agents can use the same App ID and
#     App Code, or share the same.
#     - App permissions: Set it to 'Read/Write'.
#     - App security: set it to 'User Token' by now.
#  -In the Administration/Groups section, create a new group for scan agents.
#  -In the Administation/Sections section, create edit all sections ad add rw
#     permissions for the new group for scan agents.
#  -In the Administration/Users section, create one or more users for your scan agents.
#     Agents can use the same user or different users. Add users to the new group
#     for scan agents.
#     - User role: set it to normal user.
#     - Authentication method: set it to local.

echo "Setting environment for MYIPAMClient.py"
# Set this variables with the needed values to allow this agent to the phpIPAM server
#   Each scan agent can use different credentials or share the same.
export MYIPAM_URL="https://myphpipam.example.com"
export MYIPAM_APPID="myipamclient"
export MYIPAM_TOKEN="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export MYIPAM_USER="myipamuser"
# If you don't provide this variable, the connection function will ask for the
#   password interactively.
export MYIPAM_PASSWD="ppppppppppppppppppppp"
# SSL not tested yet (use NONE to connect without SSL)
#   If you want to use SSL, set the path to the CA certificate file in PEM format.
export MYIPAM_CACERT="NONE"

echo "MYIPAM_URL=$MYIPAM_URL"
echo "MYIPAM_USER=$MYIPAM_USER"
#echo "MYIPAM_CACERT=$MYIPAM_CACERT"

################################################################################
# Scanning agent configuration
################################################################################

# Before running this script, go to phpIPAM server as admin user
#  -In the Administration/Scan agents section, create one or more scan agents
#    and set the SCANAGENT_CODE to the code of the scan agent launched by this script.
#    Each scan agent should have a different code to differentiate them.
#    Each agent will get the set of subnets assigned to it from the phpIPAM server.

# ESX PRIVATE agent
export SCANAGENT_CODE='code-of-scan-agent-generated-by-phpipam'

# This variables are global to this scan agent for all subnets scanned by it.
# Time between discovery scans (new addresses are added only during discovery scans)
export SCANAGENT_DISCOVERY_INTERVAL=7200
# Time between rescans (during rescans, last seen timestamp and some other fiedls are
#   updated, but no new addresses are added)
export SCANAGENT_RESCAN_INTERVAL=850
# The scan agent wakes up every SCANAGENT_POLL_INTERVAL seconds to get again the list
#   of subnets to scan and to check if a new rescan or discovery scan is needed.
export SCANAGENT_POLL_INTERVAL=900
# If set to 1, the scan agent will try to detect the OS of the scanned devices during
#   the discovery scan. This is done by using nmap and the nmap OS detection feature.
export SCANAGENT_OSDETECT=1

echo "SCANAGENT_RESCAN_INTERVAL=$SCANAGENT_RESCAN_INTERVAL"
echo "SCANAGENT_DISCOVERY_INTERVAL=$SCANAGENT_DISCOVERY_INTERVAL"
echo "SCANAGENT_POLL_INTERVAL=$SCANAGENT_POLL_INTERVAL"

echo Add -fD and/or -fR to force an immediate discovery or rescan after starting the agent.
echo 'Example: $HOME/.local/bin/ipamscanagent -v -fD -fR'
echo 'Example: python3 -m ipamtools.ipamScanAgent -v -fD -fR'
echo " "
echo " "

# Launch Scan Agent

# echo "$HOME/.local/bin/ipamscanagent $@"
# $HOME/.local/bin/ipamscanagent $@

# This way of launching the script is OS independent (python3 must be the default python interpreter)
echo "python -m ipamtools.ipamScanAgent $@"
python -m ipamtools.ipamScanAgent $@