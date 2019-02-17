
#
#  Basic script to search through net devices capturing IP info 
#

import os
import getopt
import sys
import re
from easysnmp import Session
from datetime import datetime

#--------------------------------------------------------------------------------

# hostnames visited, for recursion
_visitedDevices=[]

# complete list of IP's found
_totalIpList=[]

# "global" list of preferred interfaces.  Index in list represents priority (0: higher)
_prefInterfaces=[]

#  list of selected interfaces according to file (preferred)
_selectedInterfaces=[]

#  list of ALL interfaces found in network 
_networkInterfaces=[]


_snmp_version=1
_snmp_timeout=2   # in seconds
_snmp_retries=2     # retries before failure

_oid_deviceID=                      ".1.3.6.1.2.1.47.1.1.1.1.11.1"
_oid_deviceHostname=          ".1.3.6.1.2.1.1.5.0"

_oid_ipAdEntAddr=                "1.3.6.1.2.1.4.20.1.1"
_oid_ipAdEntIfIndex=             "1.3.6.1.2.1.4.20.1.2"
_oid_ipAdEntNetMask=          "1.3.6.1.2.1.4.20.1.3"

_oid_ipCidrRouteNextHop=    ".1.3.6.1.2.1.4.24.4.1.4"
_oid_ipCidrRouteMask=         ".1.3.6.1.2.1.4.24.4.1.2"

_oid_interfaceIndex=             ".1.3.6.1.2.1.2.2.1.1"
_oid_interfaceName =           ".1.3.6.1.2.1.2.2.1.2"

# global variable for verbosity level
_verbose=0

# routing table IP      .1.3.6.1.2.1.4.21.1.1
# routing table mask  .1.3.6.1.2.1.4.21.1.11
# address table IP      .1.3.6.1.2.1.4.20.1.1
# address table mask  .1.3.6.1.2.1.4.20.1.3

#--------------------------------------------------------------------------------

class interface(object):
	id = None
	ip = None
	netmask = None
	preferred = False
	priority = 200
	name = None
	session = None
	snmpReachable=False

    # --------------------- 
	def __init__(self):
		pass
		
	def printData(self):
		print "interface ID: " + self.id + " Name: " + self.name + " IP: " + self.ip + " / " + self.netmask + " Priority: " + str(self.priority)
		
#--------------------------------------------------------------------------------
		
# this is a simple recursive function in python to show teh discovery mechanism 
# in a topology that INCLUDES LOOPS (the recursive search has to end!)

#--------------------------------------------------------------------------------

def scanNet(ip, community):
	interfaces=[]
	nextHops=[]
	session = Session(ip, community=community, version=1)

	# check if this IP is reachable
	try:
		hostname = session.get(_oid_deviceHostname).value
#		deviceID = session.get(_oid_deviceID).value            ## THIS MUST BE REAL LINE FOR OPERATION 
		deviceID = session.get(_oid_deviceHostname).value
	except:
		print " Interface UNREACHABLE through SNMP ! (" + ip + ")" 
		return 
    
	if  any(x == deviceID for x in _visitedDevices):   # already visited!
		return
	else: 
		print "I will scan device " + deviceID + " with IP: " + ip
		_visitedDevices.append(deviceID)	

	## address entries
	ipAdEntAddr = [o.value for o in session.walk( _oid_ipAdEntAddr )]
	ipAdEntIfIndex =  [o.value for o in session.walk( _oid_ipAdEntIfIndex )]
	ipAdEntNetMask =  [o.value for o in session.walk( _oid_ipAdEntNetMask )]

	for item in ipAdEntAddr:
		if not any(x == item for x in _totalIpList):
			_totalIpList.append(item)		
			
	## interfaces
	interfaceIndex =  [o.value for o in session.walk( _oid_interfaceIndex )]
	interfaceName =  [o.value for o in session.walk( _oid_interfaceName )]	

	if  len(ipAdEntAddr) != len(ipAdEntIfIndex) or len(ipAdEntIfIndex) != len(ipAdEntNetMask):
		print "\n\n ERROR:  _oid_ipAdEntAddr / mask / index:  different length in captured lists!"
		system.exit(0)	

	if  len(interfaceIndex) != len(interfaceName):
		print "\n\n ERROR:  interfaceIndex / interfaceName :  different length in captured lists!"
		system.exit(0)	
	
	# compose interfaces with ip, mask, name, etc. to compare with file
	for i in range(len(interfaceName)):
		ifAux=interface()
		ifAux.name=interfaceName[i]
		ifAux.id=interfaceIndex[i]

		# search for names in preferred interfaces, if present, get priority
		try:
			preferredIndex = _prefInterfaces.index(interfaceName[i])
		except ValueError:
			preferredIndex = -1
			ifPreferred=False
		if preferredIndex >= 0:
			ifAux.priority=preferredIndex
			ifAux.preferred=True

		# search for interface index in Adresses
		try:
			positionInAddressList = ipAdEntIfIndex.index(interfaceIndex[i])
		except ValueError:
			positionInAddressList = -1
		if positionInAddressList >= 0:
			ifAux.ip=ipAdEntAddr[positionInAddressList]
			ifAux.netmask=ipAdEntNetMask[positionInAddressList]

		# add valid interfaces to list
		if ifAux.ip:
			if not any(x.ip == ifAux.ip for x in interfaces):			# local list
				interfaces.append(ifAux)	
			if not any(x == ifAux.ip for x in _totalIpList):
				_totalIpList.append(ifAux.ip)	
			if not any(x.ip == ifAux.ip for x in _networkInterfaces):    # global list
				_networkInterfaces.append(ifAux)	
	
	# now interfaces has a 'priority' attribute,  based on its existence on the configuration file	
	for item in sorted(interfaces, key=lambda object1: object1.priority, reverse=False):
		#  verify SNMP reachability
		intReachable=True
		localSession = Session(item.ip, community=community, version=1)
		try:
			hname = localSession.get(_oid_deviceHostname).value
		except:
			print " Interface " + item.ip + " UNREACHABLE through SNMP ! " 
			intReachable=False
		
		if intReachable:
			print "Selected interface for router: " + 	hostname + " is :"
			item.printData()
			_selectedInterfaces.append(item)
			break;

	# next hops
	items = session.walk('.1.3.6.1.2.1.4.24.4.1.4')
	for item in items:
	    m = re.match("0\.0\.0\.0", item.value)
    	    if not m:
		if not any(x == item.value for x in interfaces):
		    if not any(x == item.value for x in nextHops):
			nextHops.append(item.value)

		# add to total list if not already present!
		if not any(x == item.value for x in _totalIpList):
		    _totalIpList.append(item.value)

	for x in nextHops:
	    scanNet(x, community)

#--------------------------------------------------------------------------------

# read specific file for interface monitoring preference.  Format example:
#
# Loopback 0
# Loopback 5
# GigabitEthernet0/1

def readConfigFile(filename='./prefInt'):
	global _prefInterfaces
	with open(filename) as f:
		_prefInterfaces = f.read().splitlines()

#--------------------------------------------------------------------------------

# Dump into file a list of selected / preferred monitoring interfaces

def dumpSelectedIPs(filename='./selected'):
	global _selectedInterfaces
	with open(filename, 'w+') as f:
		for item in sorted(_selectedInterfaces, key=lambda object1: map(int, object1.ip.split('.')), reverse=False):
			f.writelines( "%s\n" % item.ip )

#--------------------------------------------------------------------------------

# Dump into file a list of IP / Netmask found in interfaces

def dumpInterfaceIPs(filename='./interfacesIP'):
	global _networkInterfaces
	with open(filename, 'w+') as f:
		for item in sorted(_networkInterfaces, key=lambda s: map(int, s.ip.split('.')), reverse=False):
			f.writelines( "%s %s\n" % (item.ip, item.netmask))
	
#--------------------------------------------------------------------------------

# Dump into file a list of ALL IPs found  in network

def dumpAllIPs(filename='./totalIP'):
	global _totalIpList
	with open(filename, 'w+') as f:
		for item in sorted(_totalIpList, key=lambda s: map(int, s.split('.'))):	
			f.writelines( "%s\n" %  item )

#--------------------------------------------------------------------------------

def usage():
	print "\n\n"
	print "Network discovery tool.  Options:"
	print "-i IP [IP address of first device to discover.  [Required]]"
	print "-c SNMP community  [Required]"
	print "-v [Optional verbosity level.  the more 'v' the more verbose!]"
	print "-h [Print this message]"	 
	print "\n\n"

#--------------------------------------------------------------------------------
#--------------------------------------------------------------------------------

def main():
	IPAddress = None
	snmp_community=None
	communities = []
	global _verbose

	if len(sys.argv)<2:
		usage()
		sys.exit()

	try:
		opts, args = getopt.getopt(sys.argv[1:], "i:c:vh", ["help", "verbose"])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err)  # will print something like "option -a not recognized"
		usage()
		sys.exit(2)

	for o, a in opts:
		if o in ("-v", "--verbose"):
			_verbose+=1
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		elif o in ("-i"):
			IPAddress = a
		elif o in ("-c"):
			snmp_community = a
		else:
			assert False, "unhandled option"
		
	if  IPAddress is None  or snmp_community is None:
		usage()
		sys.exit(2)
						
	readConfigFile(filename='./prefInt')

	## we can start in any node if all of them are interconnected
	scanNet(IPAddress, snmp_community)
	
	_totalIpList.sort(key=lambda s: map(int, s.split('.')))
	print "Complete list of found IPs: "
	for item in _totalIpList:
		print item
		
	dumpSelectedIPs()
	dumpInterfaceIPs()
	dumpAllIPs()

#--------------------------------------------------------------------------------

if __name__ == "__main__":
    main()
    
#--------------------------------------------------------------------------------




