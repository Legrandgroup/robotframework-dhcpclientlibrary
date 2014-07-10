#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import os

import gobject
import dbus
import dbus.service
import dbus.mainloop.glib

import argparse

import subprocess

import random

import MacAddr

import threading
import time

sys.path.insert(0, '/opt/python-local/lib/python2.7/site-packages/')

from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *

progname = os.path.basename(sys.argv[0])

#import pyiface	# Commented-out... for now we are using the system's userspace tools (ifconfig, route etc...)

# DHCP types names array (index is the DHCP type)
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

DBUS_NAME = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'	# The name of bus we are creating in D-Bus
DBUS_OBJECT_PATH = '/com/legrandelectric/RobotFrameworkIPC'	# The name of the D-Bus object under which we will communicate on D-Bus
DBUS_SERVICE_INTERFACE = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'	# The name of the D-Bus service under which we will perform input/output on D-Bus

CLIENT_ID_HWTYPE_ETHER = 0x01	# HWTYPE byte as used in the client_identifier DHCP option

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


class DBusControlledDhcpClient(DhcpClient, dbus.service.Object):
	def __init__(self, conn, dbus_loop, object_path=DBUS_OBJECT_PATH, ifname = None, listen_address = '0.0.0.0', client_port = 68, server_port = 67, mac_addr = None, apply_ip = False, dump_packets = False, **kwargs):
		"""
		Instanciate a new DBusControlledDhcpClient client bound to ifname (if specified) or a specific interface address listen_address (if specified)
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
		self._last_dnsip_list = [None]
		
		self._last_serverid = None
		self._lease_valid = False
		self._last_leasetime = None
		self._request_sent = False
		
		self._parameter_list = None	# DHCP Parameter request list (options requested from the DHCP server)
		
		self._random = None
		
		self._dhcp_status_mutex = threading.Lock()	# This mutex protects writes to any of the DHCP state machine and environment (so this does not include the variables below)

		self._renew_thread = None
		self._release_thread = None
		
		self._dbus_loop = dbus_loop

		self._dbus_loop_thread = threading.Thread(target = self._loopHandleDbus)	# Start handling D-Bus messages in a background thread.
		self._dbus_loop_thread.setDaemon(True)	# dbus loop should be forced to terminate when main program exits
		self._dbus_loop_thread.start()
		
		self._on_exit_callback = None
		
		self._iface_modified = False
		
		self._apply_ip = apply_ip
		if self._apply_ip and not self._ifname:
			raise Exception('NoIfaceProvidedWithApplyIP')
		
		self._dump_packets = dump_packets
		
		if mac_addr is None:
			if self._ifname:
				self._mac_addr = MacAddr.getHwAddrForIf(ifname = self._ifname)
			elif self._listen_address != '0.0.0.0' and self._listen_address != '::':
				self._mac_addr = MacAddr.getHwAddrForIp(ip = self._listen_address)
			else:
				raise Exception('NoInterfaceProvided')
		self.genNewXid()	# Generate a random transaction ID for future packet exchanges
	
	def setOnExit(self, function):
		"""
		Set the function that will be called when this object's exit() method is called (as a result of a D-Bus message or if .exit() is called directly
		""" 
		if not hasattr(function, '__call__'):	# Argument is not callable
			raise('NotAFunction')
		self._on_exit_callback = function
	
	# D-Bus-related methods
	def _loopHandleDbus(self):
		"""
		This method should be run within a thread... This thread's aim is to run the Glib's main loop while the main thread does other actions in the meantime
		This methods will loop infinitely to receive and send D-Bus messages and will only stop looping when the value of self._loopDbus is set to False (or when the Glib's main loop is stopped using .quit()) 
		"""
		print("Starting dbus mainloop")
		self._dbus_loop.run()
		print("Stopping dbus mainloop")
	
	@dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
	def DhcpDiscoverSent(self):
		"""
		D-Bus decorated method to send the "DhcpDiscoverSent" signal
		"""
		pass
	
	@dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
	def DhcpOfferRecv(self, ip, server):
		"""
		D-Bus decorated method to send the "DhcpOfferRecv" signal
		"""
		pass
	
	@dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
	def DhcpRequestSent(self):
		"""
		D-Bus decorated method to send the "DhcpRequestSent" signal
		"""
		pass
	
	@dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
	def DhcpRenewSent(self):
		"""
		D-Bus decorated method to send the "DhcpRenewSent" signal
		"""
		pass
		
	@dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
	def DhcpReleaseSent(self, ip):
		"""
		D-Bus decorated method to send the "DhcpReleaseSent" signal
		"""
		pass
	
	@dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
	def DhcpAckRecv(self, ip, netmask, defaultgw, dns, server, leasetime):
		"""
		D-Bus decorated method to send the "DhcpAckRecv" signal
		"""
		pass

	@dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
	def IpConfigApplied(self, interface, ip, netmask, defaultgw, leasetime):
		"""
		D-Bus decorated method to send the "IpConfigApplied" signal
		"""
		pass
	
	@dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
	def IpDnsReceived(self, dns_space_sep_list):
		"""
		D-Bus decorated method to send the "IpDnsReceived" signal
		"""
		pass
	
	def exit(self):
		"""
		Cleanup object and stop all threads
		"""
		self.sendDhcpRelease()	# Release our current lease if any (this will also clear all DHCP-lease-related threads)
		self._unconfigure_iface()	# Clean up our ip configuration (revert to standard config for this interface)

		self._dbus_loop.quit()	# Stop the D-Bus main loop
		if not self._on_exit_callback is None:
			self._on_exit_callback()

	@dbus.service.method(dbus_interface = DBUS_SERVICE_INTERFACE, in_signature='', out_signature='')
	def Exit(self):
		"""
		D-Bus method to stop the DHCP client
		"""
		print("Received Exit() command from D-Bus")
		self.exit()	# Inherited dbus.service.Ibject has virtual methods written with an initial capital, so wrap around it to use our method naming convention

	@dbus.service.method(dbus_interface = DBUS_SERVICE_INTERFACE, in_signature='', out_signature='')
	def Renew(self):
		"""
		D-Bus decorated method executed when receiving the D-Bus "Renew" message call
		This method will force a renew before the renew timeout
		"""
		self.sendDhcpRenew()

	@dbus.service.method(dbus_interface = DBUS_SERVICE_INTERFACE, in_signature='', out_signature='')
	def Restart(self):
		"""
		D-Bus decorated method executed when receiving the D-Bus "Restart" message call
		This method will force restarting the whole DHCP discovery process from the beginning
		"""
		self.sendDhcpRelease()	# Release our current lease if any (this will also clear all DHCP-lease-related threads)
		self.sendDhcpDiscover()	# Restart the DHCP discovery

	@dbus.service.method(dbus_interface = DBUS_SERVICE_INTERFACE, in_signature='', out_signature='')
	def FreezeRenew(self):
		"""
		D-Bus decorated method executed when receiving the D-Bus "FreezeRenew" message call
		This method will stop any renew from being sent (even after the lease will expire)
		It will also stop any release from being sent out... basically, we will mute the DHCP client messaging to the server
		"""
		if not self._renew_thread is None: self._renew_thread.cancel()	# Cancel the renew timeout
		if not self._release_thread is None: self._release_thread.cancel()	# Cancel the release timeout
	
	@dbus.service.method(dbus_interface = DBUS_SERVICE_INTERFACE, in_signature='s', out_signature='')
	def Debug(self, msg):
		"""
		D-Bus decorated method executed when receiving the D-Bus "Debug" message call
		This method will just echo on stdout the string given as argument
		"""
		print('Received echo message from D-Bus: "' + str(msg) + '"')
	
	# IP self configuration-related methods
	def applyIpAddressFromDhcpLease(self):
		"""
		Apply the IP address and netmask that we currently have in out self._last_ipaddress and self._last_netmask (got from last lease)
		Warning : we won't check if the lease is still valid now, this is up to the caller
		""" 
		self._iface_modified = True
		cmdline = ['ifconfig', str(self._ifname), '0.0.0.0']
		print(cmdline)
		subprocess.call(cmdline)
		cmdline = ['ifconfig', str(self._ifname), str(self._last_ipaddress), 'netmask', str(self._last_netmask)]
		print(cmdline)
		subprocess.call(cmdline)
	
	def applyDefaultGwFromDhcpLease(self):
		"""
		Apply the default gatewau that we currently have in out self._last_defaultgw (got from last lease)
		Warning : we won't check if the lease is still valid now, this is up to the caller
		""" 
		self._iface_modified = True
		cmdline = ['route', 'add', 'default', 'gw', str(self._last_defaultgw)]
		print(cmdline)
		subprocess.call(cmdline)

	# DHCP-related methods
	def genNewXid(self):
		"""
		Generate a new random DHCP transaction ID
		It will be stored inside the _current_xid property of this object and used in all subsequent DHCP packets sent by this object
		It can be retrieved using getXid()
		"""
		self._dhcp_status_mutex.acquire()
		try:
			if self._random is None:
				self._random = random.Random()
				self._random.seed()
	
			self._current_xid = self._random.randint(0,0xffffffff)
		finally:
			self._dhcp_status_mutex.release()
	
	def _getXitAsDhcpOption(self):
		"""
		Get the current xid property of this object, encoded as a DhcpOption format that can be used with DhcpPacket.SetOption()
		The format returned is an array of 4 bytes
		"""
		if self._current_xid is None:
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
		We are expecting a 32-bit integer as argument xid
		"""
		self._dhcp_status_mutex.acquire()
		try:
			self._current_xid = xid
		finally:
			self._dhcp_status_mutex.release()
	
	def getXid(self):
		"""
		Get the transaction ID that is currently used for all DHCP packets sent by us
		"""
		return self._current_xid
	
	def _unconfigure_iface(self):
		"""
		Unconfigure our interface (fall back to its default system config)
		Warning, we will not modify the current lease information stored in this object however
		"""
		if self._iface_modified:	# Clean up our ip configuration (revert to standard config for this interface)
			if not self._ifname:
				raise Exception('NoIfaceProvidedWithApplyIP')
			cmdline = ['ifdown', str(self._ifname)]
			print(cmdline)
			subprocess.call(cmdline)
			time.sleep(0.2)	# Grrrr... on some implementations, ifdown returns too early (before actually doing its job)
			cmdline = ['ifconfig', str(self._ifname), '0.0.0.0', 'down']	# Make sure we get rid of the IP address
			print(cmdline)
			subprocess.call(cmdline)
			cmdline = ['ifup', str(self._ifname)]
			print(cmdline)
			subprocess.call(cmdline)
			self._iface_modified = False

	def sendDhcpDiscover(self, parameter_list = None):
		"""
		Send a DHCP DISCOVER packet to the network
		"""
		# Cancel all renew and release threads
		self.sendDhcpRelease()	# Release our current lease if any (this will also clear all DHCP-lease-related threads)
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
		dhcp_discover.SetOption('dhcp_message_type', [dhcpNameToType('DISCOVER')])
		dhcp_discover.SetOption('client_identifier', [CLIENT_ID_HWTYPE_ETHER] + hwmac(self._mac_addr).list())
		if parameter_list is None:
			parameter_list =[1,	# Subnet mask
				3,	# Router
				6,	# DNS
				15,	# Domain
				42,	# NTP servers
				]
		self._parameter_list = parameter_list
		dhcp_discover.SetOption('parameter_request_list', self._parameter_list)
		#client.dhcp_socket.settimeout(timeout)
		dhcp_discover.SetOption('flags',[128, 0])
		dhcp_discover_type = dhcp_discover.GetOption('dhcp_message_type')[0]
		print("==>Sending DISCOVER")
		self._dhcp_status_mutex.acquire()
		self._request_sent = False
		self._dhcp_status_mutex.release()
		self.DhcpDiscoverSent()	# Emit DBUS signal
		self.SendDhcpPacketTo(dhcp_discover, '255.255.255.255', self._server_port)
	
	def handleDhcpOffer(self, res):
		"""
		Handle a DHCP OFFER packet coming from the network
		"""
		dhcp_offer = res
		dhcp_message_type = dhcp_offer.GetOption('dhcp_message_type')[0]
		message = "==>Received " + dhcpTypeToName(dhcp_message_type, False)
		if self._dump_packets:
			message += ' with content:'
		print(message)
		if self._dump_packets:
			print(dhcp_offer.str())
		
		proposed_ip = ipv4(dhcp_offer.GetOption('yiaddr'))
		server_id = ipv4(dhcp_offer.GetOption('server_identifier'))
		self.DhcpOfferRecv('IP ' + str(proposed_ip), 'SERVER ' + str(server_id))	# Emit DBUS signal with proposed IP address
		self.sendDhcpRequest(requested_ip = ipv4(dhcp_offer.GetOption('yiaddr')), server_id = server_id)
	
	def HandleDhcpOffer(self, res):
		"""
		Inherited DhcpClient has virtual methods written with an initial capital, so wrap around it to use our method naming convention
		"""
		self.handleDhcpOffer(res)
	
	def sendDhcpRequest(self, requested_ip = '0.0.0.0', server_id = '0.0.0.0', dstipaddr = '255.255.255.255'):
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
		dhcp_request.SetOption('ciaddr', ipv4('0.0.0.0').list())
		dhcp_request.SetOption('siaddr', ipv4('0.0.0.0').list())
		if isinstance(requested_ip, basestring):	# In python 3, this would be isinstance(x, str)
			requested_ip = ipv4(requested_ip)
		if isinstance(server_id, basestring):
			server_id = ipv4(server_id)
		dhcp_request.SetOption('dhcp_message_type', [dhcpNameToType('REQUEST')])
		dhcp_request.SetOption('client_identifier', [CLIENT_ID_HWTYPE_ETHER] + hwmac(self._mac_addr).list())
		dhcp_request.SetOption('request_ip_address', requested_ip.list())
		dhcp_request.SetOption('server_identifier', server_id.list())
		if not self._parameter_list is None:
			dhcp_request.SetOption('parameter_request_list', self._parameter_list)	# Resend the same parameter list as for DISCOVER
		#self.dhcp_socket.settimeout(timeout)
		dhcp_request.SetOption('flags', [128, 0])
		dhcp_request_type = dhcp_request.GetOption('dhcp_message_type')[0]
		print("==>Sending REQUEST")
		self.DhcpRequestSent()	# Emit DBUS signal
		self._dhcp_status_mutex.acquire()
		self._request_sent = True
		self._dhcp_status_mutex.release()
		self.SendDhcpPacketTo(dhcp_request, dstipaddr, self._server_port)
		
	def sendDhcpRenew(self, ciaddr = None, dstipaddr = '255.255.255.255'):
		"""
		Send a DHCP REQUEST to renew the current lease
		This is almost the same as the REQUEST following a DISCOVER, but we provide our client IP address here
		"""
		if not self._renew_thread is None:	# If there was a lease currently obtained
			self._renew_thread.cancel()
			self._renew_thread = None
		
		dhcp_request = DhcpPacket()
		dhcp_request.SetOption('op', [1])
		dhcp_request.SetOption('htype', [1])
		dhcp_request.SetOption('hlen', [6])
		dhcp_request.SetOption('hops', [0])
		dhcp_request.SetOption('xid', self._getXitAsDhcpOption())
		dhcp_request.SetOption('giaddr', ipv4('0.0.0.0').list())
		dhcp_request.SetOption('chaddr', hwmac(self._mac_addr).list() + [0] * 10)
		if ciaddr is None:
			if self._lease_valid:
				ciaddr = self._last_ipaddress
			else:
				raise Exception('RenewOnInvalidLease')
		dhcp_request.SetOption('ciaddr', ciaddr.list())
		dhcp_request.SetOption('siaddr', ipv4('0.0.0.0').list())
		dhcp_request.SetOption('dhcp_message_type', [dhcpNameToType('REQUEST')])
		dhcp_request.SetOption('client_identifier', [CLIENT_ID_HWTYPE_ETHER] + hwmac(self._mac_addr).list())
		if not self._parameter_list is None:
			dhcp_request.SetOption('parameter_request_list', self._parameter_list)	# Resend the same parameter list as for DISCOVER
		dhcp_request.SetOption('flags', [128, 0])
		dhcp_request_type = dhcp_request.GetOption('dhcp_message_type')[0]
		print("==>Sending REQUEST (renewing lease)")
		self.DhcpRenewSent()	# Emit DBUS signal
		self._dhcp_status_mutex.acquire()
		self._request_sent = True
		self._dhcp_status_mutex.release()
		self.SendDhcpPacketTo(dhcp_request, dstipaddr, self._server_port)
		self._renew_thread = threading.Timer(self._last_leasetime / 6, self.sendDhcpRenew, [])	# After the first renew is sent, increase the frequency of the next renew packets
		self._renew_thread.start()

	
	def sendDhcpRelease(self, ciaddr = None):
		"""
		Send a DHCP RELEASE to release the current lease
		"""
		if not self._renew_thread is None: self._renew_thread.cancel()	# Cancel the renew timeout
		if not self._release_thread is None: self._release_thread.cancel()	# Cancel the release timeout
		self._release_thread = None	# Delete pointer to our own thread handle now that we have been called
		if not self._renew_thread is None:	# If there was a lease currently obtained
			self._renew_thread = None	# Delete pointer to the renew (we have lost our lease)
			
			if not self._last_ipaddress is None:	# Do we have a lease?
				dhcp_release = DhcpPacket()
				dhcp_release.SetOption('op', [1])
				dhcp_release.SetOption('htype', [1])
				dhcp_release.SetOption('hlen', [6])
				dhcp_release.SetOption('hops', [0])
				dhcp_release.SetOption('xid', self._getXitAsDhcpOption())
				dhcp_release.SetOption('giaddr', ipv4('0.0.0.0').list())
				dhcp_release.SetOption('chaddr', hwmac(self._mac_addr).list() + [0] * 10)
				dhcp_release.SetOption('ciaddr', self._last_ipaddress.list())
				dhcp_release.SetOption('siaddr', ipv4('0.0.0.0').list())
				dhcp_release.SetOption('dhcp_message_type', [dhcpNameToType('RELEASE')])
				dhcp_release.SetOption('client_identifier', [CLIENT_ID_HWTYPE_ETHER] + hwmac(self._mac_addr).list())
				if not self._last_serverid is None:
					dhcp_release.SetOption('server_identifier', self._last_serverid.list())
				#self.dhcp_socket.settimeout(timeout)
				dhcp_release.SetOption('flags', [128, 0])
				dhcp_release_type = dhcp_release.GetOption('dhcp_message_type')[0]
				print("==>Sending RELEASE")
				self.DhcpReleaseSent('IP ' +str(self._last_ipaddress))	# Emit DBUS signal
				self._dhcp_status_mutex.acquire()
				self._request_sent = False
				
				self._last_ipaddress = None
				self._last_netmask = None
				self._last_defaultgw = None
				self._last_dnsip_list = None
				
				self._last_serverid = None
				self._last_leasetime = None
				
				self._lease_valid = False
				self._dhcp_status_mutex.release()

				self.SendDhcpPacketTo(dhcp_release, '255.255.255.255', self._server_port)
	
	def handleDhcpAck(self, packet):
		"""
		Handle a DHCP ACK packet coming from the network
		"""
		message = "==>Received ACK"
		if self._dump_packets:
			message += ' with content:'
		print(message)
		if self._dump_packets:
			print(packet.str())
		
		self._dhcp_status_mutex.acquire()
		try:
			if self._request_sent:
				self._request_sent = False
			else:
				print("Received an ACK without having sent a REQUEST")
				raise Exception('UnexpectedAck')
			
			self._last_ipaddress = ipv4(packet.GetOption('yiaddr'))
			self._last_netmask = ipv4(packet.GetOption('subnet_mask'))
			self._last_defaultgw = ipv4(packet.GetOption('router'))	# router is of type ipv4+ so we could get more than one router IPv4 address... but we only pick up the first one here
			
			self._last_dnsip_list = []
			
			dnsip_array = packet.GetOption('domain_name_server')	# DNS is of type ipv4+ so we could get more than one router IPv4 address... handle all DNS entries in a list
			for i in range(0, len(dnsip_array), 4):
				if len(dnsip_array[i:i+4]) == 4:
					self._last_dnsip_list += [ipv4(dnsip_array[i:i+4])]
			
			self._last_serverid = ipv4(packet.GetOption('server_identifier'))
			self._last_leasetime = ipv4(packet.GetOption('ip_address_lease_time')).int()
			
			self._lease_valid = True
			
			dns_space_sep = ' '.join(map(str, self._last_dnsip_list))
			
			self.DhcpAckRecv('IP ' + str(self._last_ipaddress),
				'NETMASK ' + str(self._last_netmask),
				'DEFAULTGW ' + str(self._last_defaultgw),
				'DNS ' + dns_space_sep,
				'SERVER ' + str(self._last_serverid),
				'LEASETIME ' + str(self._last_leasetime))
		finally:
			self._dhcp_status_mutex.release()
		
		print('Starting renew thread')
		if not self._renew_thread is None: self._renew_thread.cancel()	# Cancel the renew timeout
		if not self._release_thread is None: self._release_thread.cancel()	# Cancel the release timeout
		
		self._renew_thread = threading.Timer(self._last_leasetime / 2, self.sendDhcpRenew, [])
		self._renew_thread.start()
		self._release_thread = threading.Timer(self._last_leasetime, self.sendDhcpRelease, [])	# Restart the release timeout
		self._release_thread.start()
		
		if self._apply_ip and self._ifname:
			self.applyIpAddressFromDhcpLease()
			self.applyDefaultGwFromDhcpLease()
			self.IpConfigApplied(str(self._ifname), str(self._last_ipaddress), str(self._last_netmask), str(self._last_defaultgw), str(self._last_leasetime))
			self.IpDnsReceived(dns_space_sep)
	
	def HandleDhcpAck(self, packet):
		"""
		Inherited DhcpClient has virtual methods written with an initial capital, so wrap around it to use our method naming convention
		"""
		self.handleDhcpAck(packet)
	
	def handleDhcpNack(self, packet):
		"""
		Handle a DHCP NACK packet coming from the network
		Today, this will raise an exception. No processing will be done on such packets
		"""
		
		message = "==>Received NACK"
		if self._dump_packets:
			message += ' with content:'
		print(message)
		if self._dump_packets:
			print(packet.str())

		self._dhcp_status_mutex.acquire()

		self._last_ipaddress = None
		self._last_netmask = None
		self._last_defaultgw = None
		self._last_dnsip_list = []
		
		self._last_serverid = None
		self._last_leasetime = None
		self._lease_valid = False
		
		self._request_sent = False
		
		self._dhcp_status_mutex.release()
		
		raise Exception('DhcpNack')
	
	def HandleDhcpNack(self, packet):
		"""
		Inherited DhcpClient has virtual methods written with an initial capital, so wrap around it to use our method naming convention
		"""
		self.handleDhcpNack(packet)


dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)	# Use Glib's mainloop as the default loop for all subsequent code

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="This program launches a DHCP client daemon. \
It will report every DHCP client state change via D-Bus signal. \
It will also accept D-Bus method calls to change its behaviour (see Exit(), Renew(), Restart() and FreezeRenew() methods.", prog=progname)
	parser.add_argument('-i', '--ifname', type=str, help='network interface on which to send/receive DHCP packets', required=True)
	parser.add_argument('-A', '--applyconfig', action='store_true', help='apply the IP config (ip address, netmask and default gateway) to the interface when lease is obtained')
	parser.add_argument('-D', '--dumppackets', action='store_true', help='dump received packets content', default=False)
	parser.add_argument('-d', '--debug', action='store_true', help='display debug info', default=False)
	args = parser.parse_args()
	
	system_bus = dbus.SystemBus(private=True)
	gobject.threads_init()	# Allow the mainloop to run as an independent thread
	name = dbus.service.BusName(DBUS_NAME, system_bus)      # Publish the name to the D-Bus so that clients can see us
	client = DBusControlledDhcpClient(ifname = args.ifname, conn = system_bus, dbus_loop = gobject.MainLoop(), apply_ip = args.applyconfig, dump_packets = args.dumppackets)	# Instanciate a dhcpClient (incoming packets will start getting processing starting from now...)
	client.setOnExit(exit)	# Tell the client to call exit() when it shuts down (this will allow direct program termination when receiving a D-Bus Exit() message instead of waiting on client.GetNextDhcpPacket() to timeout in the loop below
	
	client.sendDhcpDiscover()	# Send a DHCP DISCOVER on the network
	
	try:
		while True:	client.GetNextDhcpPacket()	# Handle incoming DHCP packets
	finally:
		client.exit()
