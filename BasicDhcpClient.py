#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys

sys.path.insert(0, '/opt/pydhcplib2/lib/python2.7/site-packages/')

import dbus
import dbus.service
import dbus.mainloop.glib

from random import Random

import MacAddr

import threading
import time

r = Random()
r.seed()

from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *

DHCP_TYPES = ['UNKNOWN',
	'DISCOVER', # 1
	'OFFER', # 2
	'REQUEST', # 3
	'DECLINE', # 4
	'ACK', # 5
	'NACK', # 6
	'RELEASE', # 7
	'INFORM', # 8
]

DBUS_OBJECT_PATH = '/com/legrandelectric/RobotFrameworkIPC'	# The name of the D-Bus object under which we will communicate on D-Bus
DBUS_SERVICE_PATH = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'	# The name of the D-Bus service under which we will perform input/output on D-Bus

def dhcpNameToType(name, exception_on_unknown = True):
	"""
	Find a DHCP type (integer), given its name (case insentive)
	If exception_on_unknown is set to False, this function will return 0 (UNKNOWN) if not found
	Otherwise, it will raise UnknownDhcpType
	"""
	name = name.upper()
	for index, item in enumerate(DHCP_TYPES):
		if item == name:
			return index
	if exception_on_unknown:
		raise Exception('UnknownDhcpType')
	else:
		return 0
	
def dhcpTypeToName(type, exception_on_unknown = True):
	"""
	Find a DHCP name (string in uppercase), given its type (integer)
	If exception_on_unknown is set to False, this function will return 'UNKNOWN' if not found
	Otherwise, it will raise UnknownDhcpType
	"""
	
	try:
		return DHCP_TYPES[type].upper()
	except:
		if exception_on_unknown:
			raise
		else:
			return 'UNKNOWN'

class DhcpLeaseThread(threading.Thread):
	def __init__(self, basic_dhcp_client_obj, lease_time, func):
		threading.Thread.__init__(self)
		self._thread_id = thread_id
		self._dhcp_client_obj = basic_dhcp_client_obj
	
	def run(self):
		print("Starting DhcpLeaseThread on object " + str(self._dhcp_client_obj))
		time.sleep(30)
		print("Finished DhcpLeaseThread on object " + str(self._dhcp_client_obj))


class BasicDhcpClient(DhcpClient, dbus.service.Object):
	def __init__(self, conn, object_path=DBUS_OBJECT_PATH, ifname = None, listen_address = '0.0.0.0', client_port = 68, server_port = 67, mac_addr = None, **kwargs):
		"""
		Instanciate a new BasicDhcpClient client bound to ifname (if specified) or a specific interface address listen_address (if specified)
		Client listening UDP port and server destination UDP port can also be overridden from their default values
		"""
		
		# Note: **kwargs is here to make this contructor more generic (it will however force args to be named, but this is anyway good practice) and is a step towards efficient mutliple-inheritance with Python new-style-classes
		DhcpClient.__init__(self, ifname = ifname, listen_address = listen_address, client_listen_port = client_port, server_listen_port = server_port)
		dbus.service.Object.__init__(self, conn, object_path)
		
		if ifname:
			self.BindToDevice()
		if listen_address != '0.0.0.0' and listen_address != '::':	# 0.0.0.0 and :: are addresses any in IPv4 and IPv6 respectively
			self.BindToAddress()
		
		self._ifname = ifname
		self._listen_address = listen_address
		self._client_port = client_port
		self._server_port = server_port
		self._last_ipaddress = None
		self._last_netmask = None
		self._last_defaultgw = None
		self._last_serverid = None
		self._lease_valid = False
		self._request_sent = False
		if mac_addr == None:
			if self._ifname:
				self._mac_addr = MacAddr.getHwAddrForIf(ifname = self._ifname)
			elif self._listen_address != '0.0.0.' and self._listen_address != '::':
				self._mac_addr = MacAddr.getHwAddrForIp(ip = self._listen_address)
			else:
				raise Exception('NoInterfaceProvided')
		self.genNewXid()
	
	# D-Bus-related methods
	@dbus.service.signal(DBUS_SERVICE_PATH)
	def HelloSignal(self, message):
		# The signal is emitted when this method exits
		# You can have code here if you wish
		pass

	@dbus.service.method(DBUS_SERVICE_PATH)
	def emitHelloSignal(self):
		#you emit signals by calling the signal's skeleton method
		self.HelloSignal('Hello')
		return 'Signal emitted'

	@dbus.service.method(DBUS_SERVICE_PATH, in_signature='', out_signature='')
	def Exit(self):
		loop.quit()
	
	# DHCP-related methods
	def genNewXid(self):
		"""
		Generate a new random DHCP transaction ID
		It will be stored inside the _current_xid property of this object and used in all subsequent DHCP packets sent by this object
		It can be retrieved using getXid()
		"""
		self._current_xid = r.randint(0,0xffffffff)
	
	def _getXitAsDhcpOption(self):
		"""
		Get the current xid property of this object, encoded as a DhcpOption format that can be used with DhcpPacket.SetOption()
		"""
		if self._current_xid == None:
			return None
		xid = []
		decxid = self._current_xid
		for i in xrange(4):
			xid.insert(0, decxid & 0xff)
			decxid = decxid >> 8
		return xid
	
	def setXid(self, xid):
		"""
		Set the transaction ID that will be used for all subsequent DHCP packets sent by us
		"""
		self._current_xid = xid
	
	def getXid(self):
		"""
		Set the transaction ID that is currently used for all DHCP packets sent by us
		"""
		return self._current_xid
		
	def sendDhcpDiscover(self):
		"""
		Send a DHCP DISCOVER packet to the network
		"""
		dhcp_discover = DhcpPacket()
		dhcp_discover.SetOption('op', [1])
		dhcp_discover.SetOption('htype', [1])
		dhcp_discover.SetOption('hlen', [6])
		dhcp_discover.SetOption('hops', [0])
		dhcp_discover.SetOption('xid', self._getXitAsDhcpOption())
		dhcp_discover.SetOption('giaddr',ipv4('0.0.0.0').list())
		dhcp_discover.SetOption('chaddr',hwmac(self._mac_addr).list() + [0] * 10)
		dhcp_discover.SetOption('ciaddr',ipv4('0.0.0.0').list())
		dhcp_discover.SetOption('siaddr',ipv4('0.0.0.0').list())
		dhcp_discover.SetOption('dhcp_message_type',[dhcpNameToType('DISCOVER')])
		#dhcp_discover.SetOption('parameter_request_list',1)
		#client.dhcp_socket.settimeout(timeout)
		dhcp_discover.SetOption('flags',[128, 0])
		dhcp_discover_type = dhcp_discover.GetOption('dhcp_message_type')[0]
		print("==>Sending DISCOVER")
		self._request_sent = False
		self.SendDhcpPacketTo(dhcp_discover, '255.255.255.255', self._server_port)
	
	def handleDhcpOffer(self, res):
		"""
		Handle a DHCP OFFER packet coming from the network
		"""
		dhcp_offer = res
		dhcp_message_type = dhcp_offer.GetOption('dhcp_message_type')[0]
		print("==>Received " + dhcpTypeToName(dhcp_message_type, False) + " with content:")
		print(dhcp_offer.str())
		self.sendDhcpRequest(ciaddr = ipv4(dhcp_offer.GetOption('yiaddr')), siaddr = ipv4(dhcp_offer.GetOption('server_identifier')))
	
	def HandleDhcpOffer(self, res):
		"""
		Inherited DhcpClient has virtual methods written with an initial capital, so wrap around it to use our method naming convention
		"""
		self.handleDhcpOffer(res)
	
	def sendDhcpRequest(self, ciaddr = '0.0.0.0', siaddr = '0.0.0.0', dstipaddr = '255.255.255.255'):
		"""
		Send a DHCP REQUEST packet to the network
		"""
		dhcp_request = DhcpPacket()
		dhcp_request.SetOption('op', [1])
		dhcp_request.SetOption('htype', [1])
		dhcp_request.SetOption('hlen', [6])
		dhcp_request.SetOption('hops', [0])
		dhcp_request.SetOption('xid', self._getXitAsDhcpOption())
		dhcp_request.SetOption('giaddr', ipv4('0.0.0.0').list())
		dhcp_request.SetOption('chaddr', hwmac(self._mac_addr).list() + [0] * 10)
		if isinstance(ciaddr, basestring):	# In python 3, this would be isinstance(x, str)
			ciaddr = ipv4(ciaddr)
		dhcp_request.SetOption('ciaddr', ciaddr.list())
		if isinstance(siaddr, basestring):
			siaddr = ipv4(siaddr)
		dhcp_request.SetOption('siaddr', siaddr.list())
		dhcp_request.SetOption('dhcp_message_type', [dhcpNameToType('REQUEST')])
		#	dhcp_request.SetOption('parameter_request_list',1)
		#self.dhcp_socket.settimeout(timeout)
		dhcp_request.SetOption('flags', [128, 0])
		dhcp_request_type = dhcp_request.GetOption('dhcp_message_type')[0]
		print("==>Sending REQUEST")
		self._request_sent = True
		self.SendDhcpPacketTo(dhcp_request, dstipaddr, self._server_port)
		
	def sendDhcpRenew(self, ciaddr = None, dstipaddr = '255.255.255.255'):
		"""
		Send a DHCP REQUEST to renew the current lease
		This is almost the same as the REQUEST following a DISCOVER, but we provide our client IP address here
		"""
		dhcp_request = DhcpPacket()
		dhcp_request.SetOption('op', [1])
		dhcp_request.SetOption('htype', [1])
		dhcp_request.SetOption('hlen', [6])
		dhcp_request.SetOption('hops', [0])
		dhcp_request.SetOption('xid', self._getXitAsDhcpOption())
		dhcp_request.SetOption('giaddr', ipv4('0.0.0.0').list())
		dhcp_request.SetOption('chaddr', hwmac(self._mac_addr).list() + [0] * 10)
		if ciaddr == None:
			if self._lease_valid:
				ciaddr = self._last_ipaddress
			else:
				raise Exception('RenewOnInvalidLease')
		dhcp_request.SetOption('ciaddr', ciaddr.list())
		dhcp_request.SetOption('siaddr', siaddr.list())
		dhcp_request.SetOption('dhcp_message_type', [dhcpNameToType('REQUEST')])
		dhcp_request.SetOption('flags', [128, 0])
		dhcp_request_type = dhcp_request.GetOption('dhcp_message_type')[0]
		print("==>Sending REQUEST (renewing lease)")
		self._request_sent = True
		self.SendDhcpPacketTo(dhcp_request, dstipaddr, self._server_port)
	
	def handleDhcpAck(self, packet):
		print("==>Received ACK with content:")
		print(packet.str())
		if self._request_sent:
			print("DHCP server acknowledged our IP")
			self._request_sent = False
		self._lease_valid = True
		self._last_serverid = ipv4(packet.GetOption('server_identifier'))
		self._last_ipaddress = ipv4(packet.GetOption('yiaddr'))
		self._last_netmask = ipv4(packet.GetOption('subnet_mask'))
		self._last_defaultgw = ipv4(packet.GetOption('router'))
		print("We've been given IP: " + str(packet.GetOption('yiaddr')))
		print("We've been given netmask: " + str(packet.GetOption('subnet_mask')))
		print("We've been given gw: " + str(packet.GetOption('router')))# Router is of type ipv4+ so we could get more than one router IPv4 address... only consider the first one here
		
	def HandleDhcpAck(self, packet):
		"""
		Inherited DhcpClient has virtual methods written with an initial capital, so wrap around it to use our method naming convention
		"""
		self.handleDhcpAck(packet)
	
	def handleDhcpNack(self, packet):
		print("Recevied NACK")
		print(packet.str())
	
	def HandleDhcpNack(self, packet):
		"""
		Inherited DhcpClient has virtual methods written with an initial capital, so wrap around it to use our method naming convention
		"""
		self.handleDhcpNack(packet)


dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
system_bus = dbus.SystemBus(private=True)
name = dbus.service.BusName(DBUS_SERVICE_PATH, system_bus)
client = BasicDhcpClient(ifname = 'eth0', conn = system_bus)

#gobject.timeout_add(1000,client.emitHelloSignal)

client.sendDhcpDiscover()

while True :
	next_packet = client.GetNextDhcpPacket()
	if next_packet != None:
		packet_as_str=client.GetNextDhcpPacket().str()
		client.HelloSignal(packet_as_str)
		#print(packet_as_str)
	else:
		print('Waiting...')