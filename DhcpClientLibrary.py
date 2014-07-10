#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

#from __future__ import division

import os
import sys
import threading

import gobject
import dbus
import dbus.mainloop.glib

import time
import datetime
import subprocess
import signal



class DhcpClientStatus:

    """ DHCP client state machine database """

    def __init__(self):
        self.ipv4_address = None
        self.ipv4_netmask = None
        self.ipv4_defaultgw = None
        self.ipv4_dnslist = [None]
        self.ipv4_dhcpserverid = None
        self.ipv4_lease_valid = False   # Is the lease valid?
        self.ipv4_leaseduration = None  # How long the lease lasts
        self.ipv4_leaseexpiry = None    # When the lease will expire (in UTC time), as a time.struct_time object
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


def catchall_signal_handler(*args, **kwargs):
    print("Caught signal (in catchall handler) " + kwargs['dbus_interface'] + "." + kwargs['member'])
    for arg in args:
        print("        " + str(arg))


class RemoteDhcpClient:

    """ DHCP client object representing the remote DHCP client process with which we interface via D-Bus """

    POLL_WAIT = 1 / 100
    DBUS_NAME = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'    # The name of bus we are connecting to on D-Bus
    DBUS_OBJECT_PATH = '/com/legrandelectric/RobotFrameworkIPC'    # The name of the D-Bus object under which we will communicate on D-Bus
    DBUS_SERVICE_INTERFACE = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'    # The name of the D-Bus service under which we will perform input/output on D-Bus

    def __init__(self):
        """
        Instanciate a new RemoteDhcpClient object that represents a DHCP client remotely-controlled via D-Bus
        This RemoteDhcpClient object will mimic the status/methods of the remotely-controlled DHCP client so that we can interact with RemoteDhcpClient without any knowledge of the actual remotely-controller DHCP client
        """

        self._dbus_loop = gobject.MainLoop()
        self._bus = dbus.SystemBus()
        wait_bus_owner_timeout = 5  # Wait for 5s to have an owner for the bus name we are expecting
        logger.debug('Going to wait for an owner on bus name ' + RemoteDhcpClient.DBUS_NAME)
        while not self._bus.name_has_owner(RemoteDhcpClient.DBUS_NAME):
            time.sleep(0.2)
            wait_bus_owner_timeout -= 0.2
            if wait_bus_owner_timeout <= 0: # We timeout without having an ower for the expected bus name
                raise Exception('No owner found for bus name ' + RemoteDhcpClient.DBUS_NAME)
        
        logger.debug('Got an owner for bus name ' + RemoteDhcpClient.DBUS_NAME)
        gobject.threads_init()    # Allow the mainloop to run as an independent thread
        
        self._dhcp_client_proxy = self._bus.get_object(RemoteDhcpClient.DBUS_SERVICE_INTERFACE, RemoteDhcpClient.DBUS_OBJECT_PATH)
        self._dbus_iface = dbus.Interface(self._dhcp_client_proxy, RemoteDhcpClient.DBUS_SERVICE_INTERFACE)
        
        logger.debug("Connected to D-Bus")
        self._dhcp_client_proxy.connect_to_signal("IpConfigApplied",
                                                  self._handleIpConfigApplied,
                                                  dbus_interface = RemoteDhcpClient.DBUS_SERVICE_INTERFACE,
                                                  message_keyword='dbus_message')   # Handle the IpConfigApplied signal
        self._dhcp_client_proxy.connect_to_signal("IpDnsReceived",
                                                  self._handleIpDnsReceived,
                                                  dbus_interface = RemoteDhcpClient.DBUS_SERVICE_INTERFACE,
                                                  message_keyword='dbus_message')   # Handle the IpDnsReceived signal
        #Lionel: this is for D-Bus debugging only
        #self._bus.add_signal_receiver(catchall_signal_handler, interface_keyword='dbus_interface', member_keyword='member')
        self._dbus_loop_thread = threading.Thread(target = self._loopHandleDbus)    # Start handling D-Bus messages in a background thread
        self._dbus_loop_thread.setDaemon(True)    # dbus loop should be forced to terminate when main program exits
        self._dbus_loop_thread.start()
        
        self.status = DhcpClientStatus()
        
    # D-Bus-related methods
    def _loopHandleDbus(self):
        """
        This method should be run within a thread... This thread's aim is to run the Glib's main loop while the main thread does other actions in the meantime
        This methods will loop infinitely to receive and send D-Bus messages and will only stop looping when the value of self._loopDbus is set to False (or when the Glib's main loop is stopped using .quit()) 
        """
        logger.debug("Starting dbus mainloop")
        self._dbus_loop.run()
        logger.debug("Stopping dbus mainloop")
        
    
    def _handleIpConfigApplied(self, interface, ip, netmask, defaultgw, leasetime, **kwargs):
        self.status.ipv4_address = ip
        self.status.ipv4_netmask = netmask
        self.status.ipv4_defaultgw = defaultgw
        self.status.ipv4_lease_valid = True
        self.status.ipv4_leaseduration = leasetime
        self.status.ipv4_leaseexpiry = datetime.datetime.now() + datetime.timedelta(seconds = int(leasetime))    # Calculate the time when the lease will expire
        logger.debug('Lease obtained for IP: ' + ip + '. Will expire at ' + str(self.status.ipv4_leaseexpiry)) 
        # Lionel: FIXME: should start a timeout here to make the lease invalid at expiration 
        
    
    def _handleIpDnsReceived(self, dns_space_sep_list, **kwargs):
        self.status.ipv4_dnslist = dns_space_sep_list.split(' ')
        logger.debug('Got DNS list: ' + str(self.status.ipv4_dnslist))
        
    def _discard(self):
        logger.debug('Got called!')
        
    def exit(self):
        """
        Send an Exit message to the remote DHCP client via D-Bus
        """
        # Stop the dbus loop
        if not self._dbus_loop is None:
            self._dbus_loop.quit()
        
        if self._dbus_iface is None:
            raise Exception('Method invoked on non existing D-Bus interface')
        
        logger.debug('Sending Exit() to remote DHCP client')
        self._dbus_iface.Exit(reply_handler = self._discard, error_handler = self._discard) # Call Exit() but ignore whether it gets acknowledged or not... this is because slave process may terminate before even acknowledge

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
        self._remote_dhcp_client = None    # Slave process not started
        self._slave_dhcp_client_path = dhcp_client_daemon_exec_path
        self._slave_dhcp_client_proc = None
        self._slave_dhcp_client_pid = None
        self._ifname = ifname
        
    def _reconnect(self):
        """
        Lionel: FIXME: what does the following comment from Tristan means?
        reconnect can connect if debug was stop or restarted and flush ingoing message
        """

        self._remote_dhcp_client.disconnect()
        self._remote_dhcp_client.connect()


    def start(self):
        """Start the DHCP client
        
        Example:
        | Start |
        """
        
        try:
            cmd = ['sudo', self._slave_dhcp_client_path, '-i', self._ifname, '-A']
            logger.debug('Running command ' + str(cmd))
            self._slave_dhcp_client_proc = subprocess.Popen(cmd)#, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
            self._slave_dhcp_client_pid = self._slave_dhcp_client_proc.pid
            #time.sleep(1)   # Wait until child registers to D-Bus
        except:
            raise   # No exception handling for now
        self._remote_dhcp_client = RemoteDhcpClient()    # Create a RemoteDhcpClient object that symbolizes the control on the remote process (over D-Bus)
        logger.debug("Now connected to D-Bus")
        
#===============================================================================
# If we want to be notified when child exists and releases the bus, we can use:
#         def rhythmbox_owner_changed(new_owner):
#             if new_owner == '':
#                 print 'Rhythmbox is no longer running'
#             else:
#                 print 'Rhythmbox is now running'
# 
#             bus.watch_name_owner('org.gnome.Rhythmbox')
#===============================================================================
        
    def stop(self):
        """ Stop the DHCP client

        Example:
        | Stop |
        """

        if not self._slave_dhcp_client_proc is None:
            if not self._remote_dhcp_client is None:
                self._remote_dhcp_client.exit()
            
            if not self._slave_dhcp_client_pid is None:
                print('Sending SIGINT to child')
                if not self._slave_dhcp_client_proc.poll():
                    print('Child has already terminated')
                else:
                    args = ['sudo', 'kill', '-SIGINT', str(self._slave_dhcp_client_pid)]    # Send Ctrl+C to slave DHCP client process
                    subprocess.check_call(args, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
                    # Lionel: FIXME: we should check if slave process terminates or not within 1s else send a SIGKILL
                    self._slave_dhcp_client_pid = None
                    self._slave_dhcp_client_proc.wait()
            self._slave_dhcp_client_proc = None
    
    def restart(self):
        """ Restart the DHCP client

        Example:
        | Restart |
        """

        self.stop()
        self.start()
        self._remote_dhcp_client.connect()


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
#         temp = self._remote_dhcp_client.service_database.get_key_from_address(address)
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
#         temp = self._remote_dhcp_client.service_database.get_key_from_address(address)
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
#         temp = self._remote_dhcp_client.service_database.get_address_from_mac(mac)
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
#         ret = self._remote_dhcp_client.service_database.get_info_from_key(key)[0]
#         ret = unicode(ret)
#         return ret
#===============================================================================

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)    # Use Glib's mainloop as the default loop for all subsequent code

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
    
    client = DhcpClientLibrary(DHCP_CLIENT_DAEMON, 'eth1')
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

