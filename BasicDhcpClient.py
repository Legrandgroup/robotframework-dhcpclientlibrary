#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys

sys.path.insert(0, '/mnt/exported/dydhcplib/lib/python2.7/site-packages/')

import dbus
import dbus.service
import dbus.mainloop.glib

from random import Random
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


class BasicDhcpClient(DhcpClient, dbus.service.Object):
	def __init__(self, conn, object_path=DBUS_OBJECT_PATH, ifname = None, listen_address = '0.0.0.0', client_port = 68, server_port = 67, **kwargs):
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
		self._current_xid = xid
	
	def getXid(self):
		return self._current_xid
		
	def sendDhcpDiscover(self):
		"""
		Send a DHCP DISCOVER packet to the network
		"""
		req = DhcpPacket()
		req.SetOption('op', [1])
		req.SetOption('htype', [1])
		req.SetOption('hlen', [6])
		req.SetOption('hops', [0])
		req.SetOption('xid', self._getXitAsDhcpOption())
		req.SetOption('giaddr',ipv4('0.0.0.0').list())
		req.SetOption('chaddr',hwmac('00:12:34:56:78:9a').list() + [0] * 10)
		req.SetOption('ciaddr',ipv4('0.0.0.0').list())
		req.SetOption('siaddr',ipv4('0.0.0.0').list())
		req.SetOption('dhcp_message_type',[dhcpNameToType('DISCOVER')])
		#	req.SetOption('parameter_request_list',1)
		#client.dhcp_socket.settimeout(timeout)
		req.SetOption('flags',[128, 0])
		req_type = req.GetOption('dhcp_message_type')[0]
		print("Sending " + dhcpTypeToName(req_type))
		self.SendDhcpPacketTo(req, "255.255.255.255", self._server_port)
	
	def handleDhcpOffer(self, res):
		"""
		Handle a DHCP OFFER packet coming from the network
		"""
		dhcp_message_type = res.GetOption('dhcp_message_type')[0]
		print("Received " + dhcpTypeToName(dhcp_message_type, False))
		print(res.str())
		server_identifier = ipv4(res.GetOption('server_identifier'))
		chaddr = hwmac(res.GetOption('chaddr')[:6])
		yiaddr = ipv4(res.GetOption('yiaddr'))
		request_ciaddr = yiaddr.str()
		serverip = server_identifier.str()
		request_dhcp_message_type = 'request'
		req2 = DhcpPacket()
		req2.SetOption('op',[1])
		req2.SetOption('htype',[1])
		req2.SetOption('hlen',[6])
		req2.SetOption('hops',[0])
		req2.SetOption('xid', self._getXitAsDhcpOption())
		req2.SetOption('giaddr',ipv4('0.0.0.0').list())
		req2.SetOption('chaddr',hwmac('00:12:34:56:78:9a').list() + [0] * 10)
		req2.SetOption('ciaddr',yiaddr.list())
		req2.SetOption('siaddr',server_identifier.list())
		req2.SetOption('dhcp_message_type',[dhcpNameToType('REQUEST')])
		#	req2.SetOption('parameter_request_list',1)
		#self.dhcp_socket.settimeout(timeout)
		req2.SetOption('flags',[128, 0])
		req2_type = req2.GetOption('dhcp_message_type')[0]
		print("Sending " + dhcpTypeToName(req2_type))
		self.SendDhcpPacketTo(req2, serverip, self._server_port)
	
	def HandleDhcpOffer(self, res):
		"""
		Inherited DhcpClient has virtual methods written with an initial capital, so wrap around it to use our method naming convention
		"""
		self.handleDhcpOffer(res)
	
	def handleDhcpAck(self, packet):
		print("Received ACK")
		print(packet.str())
		
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


print(sys.path)
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
system_bus = dbus.SystemBus(private=True)
name = dbus.service.BusName(DBUS_SERVICE_PATH, system_bus)
client = BasicDhcpClient(ifname = 'eth0', conn = system_bus)

#gobject.timeout_add(1000,client.emitHelloSignal)

client.sendDhcpDiscover()

while True :
	packet_as_str=client.GetNextDhcpPacket().str()
	client.HelloSignal(packet_as_str)
	print(packet_as_str)
