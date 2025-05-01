@echo off

@REM ################################################################################
@REM This script should be sourced instead of executed if you want to
@REM   run your tests from the command line.
@REM You can also specify the parameters as command line options to the tools.
@REM ################################################################################


@REM ################################################################################
@REM Parameters to connect to the phpIPAM service
@REM ################################################################################

@REM Before running this script, go to phpIPAM server as admin user
@REM  -In the Administration/API section, create a new App ID and App Code to allow
@REM     the access for scan agents. Several scan agents can use the same App ID and
@REM     App Code, or share the same.
@REM     - App permissions: Set it to 'Read/Write'.
@REM     - App security: set it to 'User Token' by now.
@REM  -In the Administration/Groups section, create a new group for scan agents.
@REM  -In the Administation/Sections section, create edit all sections ad add rw
@REM     permissions for the new group for scan agents.
@REM  -In the Administration/Users section, create one or more users for your scan agents.
@REM     Agents can use the same user or different users. Add users to the new group
@REM     for scan agents.
@REM     - User role: set it to normal user.
@REM     - Authentication method: set it to local.

echo Setting environment for MYIPAMClient.py
@REM Set this variables with the needed values to allow this agent to the phpIPAM server
@REM   Each scan agent can use different credentials or share the same.
set MYIPAM_URL=https://myphpipam.example.com
set MYIPAM_APPID=myipamclient
set MYIPAM_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set MYIPAM_USER=myipamuser
@REM If you don't provide this variable, the connection function will ask for the
@REM   password interactively.
set MYIPAM_PASSWD=ppppppppppppppppppppp
@REM SSL not tested yet (use NONE to connect without SSL)
@REM   If you want to use SSL, set the path to the CA certificate file in PEM format.
set MYIPAM_CACERT=NONE

echo MYIPAM_URL=%MYIPAM_URL%
echo MYIPAM_USER=%MYIPAM_USER%
@REM #echo MYIPAM_CACERT=%MYIPAM_CACERT%

@REM ################################################################################
@REM Scanning agent configuration
@REM ################################################################################

@REM Before running this script, go to phpIPAM server as admin user
@REM  -In the Administration/Scan agents section, create one or more scan agents
@REM    and set the SCANAGENT_CODE to the code of the scan agent launched by this script.
@REM    Each scan agent should have a different code to differentiate them.
@REM    Each agent will get the set of subnets assigned to it from the phpIPAM server.

@REM ESX PRIVATE agent
set SCANAGENT_CODE='code-of-scan-agent-generated-by-phpipam'

@REM This variables are global to this scan agent for all subnets scanned by it.
@REM Time between discovery scans (new addresses are added only during discovery scans)
set SCANAGENT_DISCOVERY_INTERVAL=7200
@REM Time between rescans (during rescans, last seen timestamp and some other fiedls are
@REM   updated, but no new addresses are added)
set SCANAGENT_RESCAN_INTERVAL=850
@REM The scan agent wakes up every SCANAGENT_POLL_INTERVAL seconds to get again the list
@REM   of subnets to scan and to check if a new rescan or discovery scan is needed.
set SCANAGENT_POLL_INTERVAL=900
@REM If set to 1, the scan agent will try to detect the OS of the scanned devices during
@REM   the discovery scan. This is done by using nmap and the nmap OS detection feature.
set SCANAGENT_OSDETECT=1

echo SCANAGENT_RESCAN_INTERVAL=%SCANAGENT_RESCAN_INTERVAL%
echo SCANAGENT_DISCOVERY_INTERVAL=%SCANAGENT_DISCOVERY_INTERVAL%
echo SCANAGENT_POLL_INTERVAL=%SCANAGENT_POLL_INTERVAL%

echo Add -fD and/or -fR to force an immediate discovery or rescan after starting the agent.
echo 'Example: %USERPROFILE%/.local/bin/ipam2text -v'
echo 'Example: python3 -m ipamtools.ipam2text -v'
echo  
echo  

@REM Launch ipam2text

@REM This way of launching the script depends on the python version
@REM echo %USERPROFILE%/AppData/Roaming/Python/Python312/Scripts/ipam2text %*
@REM %USERPROFILE%/AppData/Roaming/Python/Python312/Scripts/ipam2text %*

@REM This way of launching the script is OS and verson independent (python3 must be the default python interpreter)
echo python -m ipamtools.ipam2text %*
python -m ipamtools.ipam2text %*