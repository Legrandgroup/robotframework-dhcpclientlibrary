#!/usr/bin/python
# -*- coding: utf-8 -*-

import fcntl, socket, struct
import platform
import netifaces

SIOCGIFHWADDR = 0x8927	# Get MAC address for iface

def getHwAddrForIf(ifname):
	"""
	Returns the MAC address for the interface provided as argument
	"""
	if platform.system() == 'Linux':
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR,  struct.pack('256s', ifname[:15]))
		return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
	else:
		raise Exception('NotSupportedFor' + platform.system())

def getHwAddrForIp(ip):
	"""
	Returns the MAC address for the first interface that matches the given IP
	Returns None if not found
	"""
	for i in netifaces.interfaces():
		addrs = netifaces.ifaddresses(i)
		try:
			if_mac = addrs[netifaces.AF_LINK][0]['addr']
			if_ip = addrs[netifaces.AF_INET][0]['addr']
		except IndexError, KeyError: # Ignore ifaces that dont have MAC or IP
			if_mac = if_ip = None
		if if_ip == ip:
			return if_mac
	return None
