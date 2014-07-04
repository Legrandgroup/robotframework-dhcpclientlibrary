#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

#from __future__ import division

import os
import sys

import subprocess
import signal

from dbus.mainloop.glib import DBusGMainLoop

import dbus
import gobject

DBusGMainLoop(set_as_default=True)


class DhcpClientStatus:

    """ DHCP client state machine database """

    def __init__(self):
        self.ipv4_address = None
        self.ipv4_netmask = None
        self.ipv4_defaultgw = None
        self.ipv4_dnslist = [None]
        self.ipv4_dhcpserverid = None
        self.ipv4_lease_valid = False
        self.ipv4_leaseduration = None
        self.ipv4_leaseexpiry = None
        self.ipv4_dhcpclientfailure = True
        self.ipv4_dhcpclientnbfailure = 0

    def __repr__(self):
        temp = ''
        
        if self.ipv4_lease_valid is None:
            temp += 'No valid lease'
        else:
            if not self.ipv4_address is None:
                temp += 'IPv4 address: ' + str(self.ipv4_address) + '\n'
            if not self.ipv4_netmask is None:
                temp += 'IPv4 netmask: ' + str(self.ipv4_netmask) + '\n'
            if not self.ipv4_defaultgw is None:
                temp += 'IPv4 default gw: ' + str(self.ipv4_defaultgw) + '\n'
            if not self.ipv4_dnslist is None:
                for dns in self.ipv4_dnslist:
                    temp += 'IPv4 DNS:' + str(dns) + '\n'
            if not self.ipv4_dhcpserverid is None:
                temp += 'IPv4 DHCP server: ' + str(self.ipv4_dhcpserverid) + '\n'
            if not self.ipv4_leaseduration is None:
                temp += 'IPv4 lease last for: ' + str(self.ipv4_leaseduration) + 's\n'
        return temp


class RemoteDhcpClient:

    """ DHCP client object representing the remote DHCP client process with which we interface via D-Bus """

    POLL_WAIT = 1 / 100
    DBUS_NAME = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'    # The name of bus we are connecting to on D-Bus
    DBUS_OBJECT_PATH = '/com/legrandelectric/RobotFrameworkIPC'    # The name of the D-Bus object under which we will communicate on D-Bus
    DBUS_SERVICE_INTERFACE = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'    # The name of the D-Bus service under which we will perform input/output on D-Bus

    def __init__(self, loop):
        """ DBus connection """

        self._loop = loop
        self._bus = None
        self._dhcp_client_proxy = None
        self._dbus_iface = None
        self.status = DhcpClientStatus()
        
    def _wait_daemon(self, timeout=10):
        """
        Wait until the slave process daemon is available via D-Bus
        """

        maxtime = time.time() + int(timeout)
        while True:
            time.sleep(RemoteDhcpClient.POLL_WAIT)
            if time.time() > maxtime:
                logger.warn('DHCP client daemon not available')
                break
            if self.get_state() == 2:  # AVAHI_CLIENT_NO_FAIL
                logger.debug('DHCP client daemon available')
                break

    def connect(self):
        """
        Initiate the D-Bus connection to the slave process
        """

        if self._bus is None:
            try:
                self._bus = dbus.SystemBus(private=True)
                self._dhcp_client_proxy = self._bus.get_object(RemoteDhcpClient.DBUS_NAME, RemoteDhcpClient.DBUS_OBJECT_PATH)
                self._dbus_iface = dbus.Interface(self._dhcp_client_proxy, RemoteDhcpClient.DBUS_SERVICE_INTERFACE)
            except:
                raise Exception("DBus exception occurs with type '%s' and value '%s'" % sys.exc_info()[:2])
            logger.debug("DBus connected passed on '%s'" % self._bus)
            self._wait_daemon()
        else:
            logger.debug('DBus connect failed on existing instance')
        
        print('Now listening to signals')
        self._dbus_iface.connect_to_signal("DhcpAckRecv", self.handler, sender_keyword='sender')
    
    def handler(sender=None):
        print("got signal from %r" % sender)
    
    def disconnect(self):
        """
        Disconnect from slave process on D-Bus
        """

        if self._bus:
            try:
                self._bus.close()
            except:
                raise Exception("DBus exception occurs with type '%s' and value '%s'" % sys.exc_info()[:2])
            logger.debug("DBus close passed on '%s'" % self._bus)
            self._bus = None
            self._dhcp_client_proxy = None
            self._dbus_iface = None
        else:
            logger.debug('DBus close failed on null instance')

#===============================================================================
#     def get_version(self):
#         """ get version """
# 
#         if self._dbus_iface is None:
#             raise Exception('You need to connect before getting version')
#         else:
#             version = self._dbus_iface.GetVersionString()
#             return version
# 
#     def get_interface_name(self, interface_index):
#         """ get interface name from index """
# 
#         if self._dbus_iface is None:
#             raise Exception('You need to connect before getting interface name')
#         else:
#             interface_name = self._dbus_iface.GetNetworkInterfaceNameByIndex(interface_index)
#             return interface_name
# 
#     def get_state(self):
#         """ get state """
# 
#         if self._dbus_iface is None:
#             raise Exception('The D-Bus-controlled DHCP client is not running. Please start it first')
#         else:
#             state = self._dbus_iface.GetState()
#             return state
# 
#     def browse_service_type(self, stype):
#         """ browse service """
# 
#         if self._dbus_iface is None:
#             raise Exception('You need to connect before getting interface name')
#         try:
#             browser_path = self._dbus_iface.ServiceBrowserNew(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, stype, self._domain, dbus.UInt32(0))
#             browser_proxy = self._bus.get_object(avahi.DBUS_NAME, browser_path)
#             browser_interface = dbus.Interface(browser_proxy, avahi.DBUS_INTERFACE_SERVICE_BROWSER)
#             browser_interface.connect_to_signal('AllForNow', self._service_finish)
#             browser_interface.connect_to_signal('CacheExhausted', self._service_cache)
#             browser_interface.connect_to_signal('Failure', self._service_failure)
#             browser_interface.connect_to_signal('Free', self._service_free)
#             browser_interface.connect_to_signal('ItemNew', self._service_new)
#             browser_interface.connect_to_signal('ItemRemove', self._service_remove)
#         except:
#             raise Exception("DBus exception occurs in browse_service_type with type '%s' and value '%s'" % sys.exc_info()[:2])
# 
#     def _service_new(
#         self,
#         interface,
#         protocol,
#         name,
#         stype,
#         domain,
#         flags,
#         ):
#         """ add a Bonjour service in database """
# 
#         logger.debug('Avahi:ItemNew')
#         temp = self._dbus_iface.ResolveService(
#             interface,
#             protocol,
#             name,
#             stype,
#             domain,
#             avahi.PROTO_UNSPEC,
#             dbus.UInt32(0),
#             )
#         self.service_database.add(temp)
# 
#     def _service_remove(
#         self,
#         interface,
#         protocol,
#         name,
#         stype,
#         domain,
#         flags,
#         ):
#         """ remove a Bonjour service in database """
# 
#         logger.debug('Avahi:ItemRemove')
#         key = (interface, protocol, name, stype, domain)
#         self.service_database.remove(key)
# 
#     def _service_finish(self):
#         """ no more Bonjour service """
# 
#         logger.debug('Avahi:AllForNow')
#         self._loop.quit()
# 
#     def _service_failure(self, error):
#         """ avahi failure """
# 
#         logger.debug('Avahi:Failure')
#         logger.warn('Error %s' % error)
#         self._loop.quit()
# 
#     @staticmethod
#     def _service_free():
#         """ free """
# 
#         logger.debug('Avahi:Free')
# 
#     @staticmethod
#     def _service_cache():
#         """ cache """
# 
#         logger.debug('Avahi:CacheExhausted')
#===============================================================================


class DhcpClientLibrary:

    """ Robot Framework Bonjour Library """

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = '1.0'

    def __init__(self, dhcp_client_daemon_exec_path, ifname):
        self._loop = gobject.MainLoop()
        self._dhcp_client = None    # Slave process not started
        self._slave_dhcp_client_path = dhcp_client_daemon_exec_path
        self._slave_dhcp_client_proc = None
        self._slave_dhcp_client_pid = None
        self._ifname = ifname
        
    def _reconnect(self):
        """
        Lionel: FIXME: what does the following comment from Tristan means?
        reconnect can connect if debug was stop or restarted and flush ingoing message
        """

        self._dhcp_client.disconnect()
        self._dhcp_client.connect()

    def _browse_generic(self, stype):
        """
        Connect to D-Bus, and follow the slave DHCP client status
        """

        self._reconnect()
        #self._dhcp_client.service_database.reset() # Lionel: No reset available on the DHCP state machine... or slave process will have to be killed
        #self._dhcp_client.browse_service_type(stype) # Lionel: for now, don't control the RemoteDhcpClient object from here (it will do it stuff alone)
        try:
            logger.debug('DBus loop running')
            self._loop.run()
        except (KeyboardInterrupt, SystemExit):
            self._loop.quit()
            raise Exception("Exit from glib loop with type '%s' and value '%s'" % sys.exc_info()[:2])
        except:
            self._loop.quit()
            raise Exception("DBus exception occurs in browse_generic with type '%s' and value '%s'" % sys.exc_info()[:2])
        else:
            logger.debug('DBus loop ending with database:%s' % self._dhcp_client.service_database)

    def start(self):
        """Start the DHCP client
        
        Example:
        | Start |
        """
        
        try:
            args = ['sudo', self._slave_dhcp_client_path, '-i', self._ifname, '-A']
            self._slave_dhcp_client_proc = subprocess.Popen(args, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
            self._slave_dhcp_client_pid = self._slave_dhcp_client_proc.pid
        except:
            raise   # No exception handling for now 
        logger.debug("Running '%s' with argument '%s' passed" % (self._slave_dhcp_client_path, args))
        self._dhcp_client = RemoteDhcpClient(self._loop)
        self._dhcp_client.connect()
        logger.debug("Now connected to D-Bus")
        
    def stop(self):
        """ Stop the DHCP client

        Example:
        | Stop |
        """

        self._dhcp_client.disconnect()
        if not self._slave_dhcp_client_proc is None:
            # Lionel: Send D-Bus Exit() method?
            if not self._slave_dhcp_client_pid is None:
                args = ['sudo', 'kill', '-SIGINT', str(self._slave_dhcp_client_pid)]    # Send Ctrl+C to slave DHCP client process
                subprocess.check_call(args, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
                # Lionel: FIXME: we should check if slave process terminates or not within 1s else send a SIGKILL
                self._slave_dhcp_client_pid = None
            self._slave_dhcp_client_proc = None
    
    def restart(self):
        """ Restart the DHCP client

        Example:
        | Restart |
        """

        self.stop()
        self.start()
        self._dhcp_client.connect()


#===============================================================================
#     def check_run(self, address, stype='_http._tcp'):
#         """ Test if service type `stype` is present on `address`.
#         
#         Return service.
#         
#         Example:
#         | Check Run | ip | _http._tcp |
#         =>
#         | ${service} |
#         """
# 
#         self._browse_generic(stype)
#         temp = self._dhcp_client.service_database.get_key_from_address(address)
#         if temp is not None:
#             ret = temp
#         else:
#             raise Exception("Service '%s' expected on '%s'" % (stype, address))
#         return ret
# 
#     def check_stop(self, address, stype='_http._tcp'):
#         """ Test if service type `stype` is missing on `address`.
#         
#         Return service.
#         
#         Example:
#         | Check Stop | ip | _http._tcp |
#         """
# 
#         self._browse_generic(stype)
#         temp = self._dhcp_client.service_database.get_key_from_address(address)
#         if temp is not None:
#             raise Exception("Service '%s' not expected on '%s'" % (stype, address))
# 
#     def get_ip(self, mac, stype='_http._tcp'):
#         """ Get first ip address which have service type `stype` and `mac`.
#         
#         Return IP.
#         
#         Example:
#         | Get IP | 01.23.45.67.89.ab | _http._tcp |
#         =>
#         | ip |
#         """
# 
#         self._browse_generic(stype)
#         temp = self._dhcp_client.service_database.get_address_from_mac(mac)
#         if temp is not None:
#             ret = temp
#         else:
#             raise Exception("Service '%s' expected on '%s'" % (stype, mac))
#         ret = unicode(ret)
#         return ret
# 
#     def get_apname(self, key):
#         """ Get Application Point name from `key`.
#         
#         Return IP.
#         
#         Example:
#         | ${data} = | Check Run | ip | _http._tcp |
#         | Get APName | ${data} |
#         =>
#         | ${apname} |
#         """
# 
#         ret = self._dhcp_client.service_database.get_info_from_key(key)[0]
#         ret = unicode(ret)
#         return ret
#===============================================================================


if __name__ == '__main__':
    try:
        from console_logger import LOGGER as logger
    except ImportError:
        import logging

        logger = logging.getLogger('console_logger')
        logger.setLevel(logging.DEBUG)
        
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)

    try:
        input = raw_input
    except NameError:
        pass

    DHCP_CLIENT_DAEMON = None
    # Try to guess the location of dut_console_get_uboot_prompt.py
    connect_tool_dir = os.path.abspath(os.path.dirname(sys.argv[0]))        # Find our current directory (absolute path)
    DHCP_CLIENT_DAEMON = connect_tool_dir + '/DBusControlledDhcpClient.py'     # Add the default script name
    
    if os.path.isfile(DHCP_CLIENT_DAEMON):
        logger.debug('Autoselecting DHCP Client slave as "' + DHCP_CLIENT_DAEMON + '"')
    
    client = DhcpClientLibrary(DHCP_CLIENT_DAEMON, 'eth0')
    client.start()
    input('Press enter to stop slave')
    client.stop()
    #assert IP == client.get_ip(MAC, '_http._tcp')
    #DATA = BL.check_run(IP, '_http._tcp')
    #BL.get_apname(DATA)
    #input('Press enter & "Disable UPnP/Bonjour" on web interface')
    #BL.check_stop(IP, '_http._tcp')
else:
    from robot.api import logger

