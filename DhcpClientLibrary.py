#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

#from __future__ import division

import os
import sys
import threading
import atexit

import gobject
import dbus
import dbus.mainloop.glib

import time
import datetime
import subprocess
import signal


all_processes_pid = []  # List of all subprocessed launched by us

def checkPid(pid):        
    """
    Check For the existence of a UNIX PID
    """
    
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True
    
def killSubprocessFromPid(pid, log = True):
    """
    Kill a process from it PID (first send a SIGINT, then at give it a maximum of 1 second to terminate and send a SIGKILL if is still alive after this timeout
    """

    if log: logger.info('Sending SIGINT to slave PID ' + str(pid))
    args = ['sudo', 'kill', '-SIGINT', str(pid)]    # Send Ctrl+C to slave DHCP client process
    subprocess.call(args, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
            
    timeout = 1 # Give 1s for slave process to exit
    while checkPid(pid):  # Loop if slave process is still running
        time.sleep(0.1)
        timeout -= 0.1
        if timeout <= 0:    # We have reached timeout... send a SIGKILL to the slave process to force termination
            if log: logger.info('Sending SIGKILL to slave PID ' + str(pid))
            args = ['sudo', 'kill', '-SIGKILL', str(pid)]    # Send Ctrl+C to slave DHCP client process
            subprocess.call(args, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
            break

def cleanupAtExit():
    """
    Called when this program is terminated, to terminate all the subprocesses that are still running
    """
    
    global all_processes_pid
    
    for pid in all_processes_pid: # list of your processes
        logger.warning("Stopping slave PID " + str(pid))
        killSubprocessFromPid(pid, log = False)

class DhcpLeaseStatus:
    """
    This object represents a DHCP lease status database
    """

    def __init__(self):
        #self._dhcp_status_mutex = threading.Lock()    # This mutex protects writes to any of the variables of this object
        self.reset()

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
    
    def reset(self):
        """
        Reset internal attribute to no lease state
        """
        with self._dhcp_status_mutex:
            self.ipv4_address = None
            self.ipv4_netmask = None
            self.ipv4_defaultgw = None
            self.ipv4_dnslist = [None]
            self.ipv4_dhcpserverid = None
            self.ipv4_lease_valid = False   # Is the lease valid?
            self.ipv4_leaseduration = None  # How long the lease lasts
            #self.ipv4_lease_remaining   # For how long the lease is still valid?
            self.ipv4_leaseexpiry = None    # When the lease will expire (in UTC time), as a time.struct_time object

    #===========================================================================
    # @property
    # def ipv4_lease_remaining(self):
    #     return 0    # FIXME: we should perform some calculation here
    # 
    #  
    # @flags.setter
    # def ipv4_address(self, val):
    #     self._dhcp_status_mutex.acquire()
    #     try:
    #         self.ipv4_address = val
    #     finally:
    #         self._dhcp_status_mutex.release()
    #===========================================================================

def catchall_signal_handler(*args, **kwargs):
    print("Caught signal (in catchall handler) " + kwargs['dbus_interface'] + "." + kwargs['member'])
    for arg in args:
        print("        " + str(arg))


class RemoteDhcpClientControl:

    """
    DHCP client object representing a remote (slave) DHCP client process
    This slave process must already be running (we won't launch it ourselves)
    Will will communicate with this slave using D-Bus Methods and catch the D-Bus signals it emits
    """

    POLL_WAIT = 1 / 100
    DBUS_NAME = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'    # The name of bus we are connecting to on D-Bus
    DBUS_OBJECT_PATH = '/com/legrandelectric/RobotFrameworkIPC/DhcpClientLibrary'    # The name of the D-Bus object under which we will communicate on D-Bus
    DBUS_SERVICE_INTERFACE = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'    # The name of the D-Bus service under which we will perform input/output on D-Bus

    def __init__(self):
        """
        Instanciate a new RemoteDhcpClientControl object that represents a DHCP client remotely-controlled via D-Bus
        This RemoteDhcpClientControl object will mimic the status/methods of the remotely-controlled DHCP client so that we can interact with RemoteDhcpClientControl without any knowledge of the actual remotely-controller DHCP client
        """

        self._dbus_loop = gobject.MainLoop()
        self._bus = dbus.SystemBus()
        wait_bus_owner_timeout = 5  # Wait for 5s to have an owner for the bus name we are expecting
        logger.debug('Going to wait for an owner on bus name ' + RemoteDhcpClientControl.DBUS_NAME)
        while not self._bus.name_has_owner(RemoteDhcpClientControl.DBUS_NAME):
            time.sleep(0.2)
            wait_bus_owner_timeout -= 0.2
            if wait_bus_owner_timeout <= 0: # We timeout without having an ower for the expected bus name
                raise Exception('No owner found for bus name ' + RemoteDhcpClientControl.DBUS_NAME)
        
        logger.debug('Got an owner for bus name ' + RemoteDhcpClientControl.DBUS_NAME)
        gobject.threads_init()    # Allow the mainloop to run as an independent thread
        dbus.mainloop.glib.threads_init()
        
        self._dhcp_client_proxy = self._bus.get_object(RemoteDhcpClientControl.DBUS_SERVICE_INTERFACE, RemoteDhcpClientControl.DBUS_OBJECT_PATH)
        self._dbus_iface = dbus.Interface(self._dhcp_client_proxy, RemoteDhcpClientControl.DBUS_SERVICE_INTERFACE)
        
        logger.debug("Connected to D-Bus")
        self._dhcp_client_proxy.connect_to_signal("IpConfigApplied",
                                                  self._handleIpConfigApplied,
                                                  dbus_interface = RemoteDhcpClientControl.DBUS_SERVICE_INTERFACE,
                                                  message_keyword='dbus_message')   # Handle the IpConfigApplied signal
        
        self._dhcp_client_proxy.connect_to_signal("LeaseLost",
                                                  self._handleLeaseLost,
                                                  dbus_interface = RemoteDhcpClientControl.DBUS_SERVICE_INTERFACE,
                                                  message_keyword='dbus_message')   # Handle the IpConfigApplied signal
        
        #Lionel: the following line is used for D-Bus debugging only
        #self._bus.add_signal_receiver(catchall_signal_handler, interface_keyword='dbus_interface', member_keyword='member')
        self._dbus_loop_thread = threading.Thread(target = self._loopHandleDbus)    # Start handling D-Bus messages in a background thread
        self._dbus_loop_thread.setDaemon(True)    # D-Bus loop should be forced to terminate when main program exits
        self._dbus_loop_thread.start()
        
        self._bus.watch_name_owner(RemoteDhcpClientControl.DBUS_NAME, self._handleBusOwnerChanged) # Install a callback to run when the bus owner changes
        
        self._callback_new_lease_mutex = threading.Lock()    # This mutex protects writes to the _callback_new_lease attribute
        self._callback_new_lease = None
        
        self._exit_unlock_event = threading.Event() # Create a new threading event that will allow the exit() method to wait for the child to terminate properly
        self._getversion_unlock_event = threading.Event() # Create a new threading event that will allow the GetVersion() D-Bus call below to execute within a timed limit 

        self.status_mutex = threading.Lock()    # This mutex protects writes to the status attribute
        self.status = DhcpLeaseStatus()

        self._getversion_unlock_event.clear()
        self._remote_version = ''
        slave_version = self._dbus_iface.GetVersion(reply_handler = self._getVersionUnlock, error_handler = self._getVersionError)
        if not self._getversion_unlock_event.wait(2):   # We give 2s for slave to answer the GetVersion() request
            raise Exception('TimeoutOnGetVersion')
        logger.debug('Slave announces version: ' + self._remote_version)
        
    # D-Bus-related methods
    def _loopHandleDbus(self):
        """
        This method should be run within a thread... This thread's aim is to run the Glib's main loop while the main thread does other actions in the meantime
        This methods will loop infinitely to receive and send D-Bus messages and will only stop looping when the value of self._loopDbus is set to False (or when the Glib's main loop is stopped using .quit()) 
        """
        logger.debug("Starting dbus mainloop")
        self._dbus_loop.run()
        logger.debug("Stopping dbus mainloop")
        
    
    def _getVersionUnlock(self, return_value):
        """
        This method is used as a callback for asynchronous D-Bus method call to GetVersion()
        It is run as a reply_handler to unlock the wait() on _getversion_unlock_event
        """
        #logger.debug('_getVersionUnlock() called')
        self._remote_version = str(return_value)
        self._getversion_unlock_event.set() # Unlock the wait() on self._getversion_unlock_event
        
    def _getVersionError(self, remote_exception):
        """
        This method is used as a callback for asynchronous D-Bus method call to GetVersion()
        It is run as an error_handler to raise an exception when the call to GetVersion() failed
        """
        logger.error('Error on invocation of GetVersion() to slave, via D-Bus')
        raise Exception('ErrorOnDBusGetVersion')
        
    def notifyNewLease(self, callback):
        """
        This method will call the specified callback when the lease becomes valid (or will call it immediately if it is already vali
        callback must me callable or an exception will be raised
        """
        if not hasattr(callback, '__call__'):
            raise Exception('WrongCallback')
        else:
            with self.status_mutex:
                if self.status.ipv4_lease_valid:
                    callback()  # Call callback function right now if lease is already valid
                else:   # We still hold the mutex here because we don't want ipv4_lease_valid to be changed before we install the callback ;-)
                    with self._callback_new_lease_mutex:
                        self._callback_new_lease = callback
    
    def _handleIpConfigApplied(self, interface, ip, netmask, defaultgw, leasetime, dns_space_sep, **kwargs):
        """
        Method called when receiving the IpConfigApplied signal from the slave process
        """
        logger.debug('Got signal IpConfigApplied')
        with self.status_mutex:
            self.status.ipv4_address = ip
            self.status.ipv4_netmask = netmask
            self.status.ipv4_defaultgw = defaultgw
            self.status.ipv4_lease_valid = True
            self.status.ipv4_leaseduration = leasetime
            self.status.ipv4_leaseexpiry = datetime.datetime.now() + datetime.timedelta(seconds = int(leasetime))    # Calculate the time when the lease will expire
            logger.debug('Lease obtained for IP: ' + ip + '. Will expire at ' + str(self.status.ipv4_leaseexpiry))
            self.status.ipv4_dnslist = dns_space_sep.split(' ')
            if self.status.ipv4_dnslist:
                logger.debug('Got DNS list: ' + str(self.status.ipv4_dnslist))
        with self._callback_new_lease_mutex:
            if not self._callback_new_lease is None:    # If we have a callback to call when lease becomes valid
                self._callback_new_lease()    # Do the callback

        # Lionel: FIXME: should start a timeout here to make the lease invalid at expiration (note: the client also does the same, and should issue a LeaseLost signal accordingly but just in case, shouldn't we double check on this side? 
        
    def _handleLeaseLost(self, **kwargs):
        logger.debug('Got signal LeaseLost')
        self.status.reset() # Reset all data about the previous lease
    
    def _handleBusOwnerChanged(self, new_owner):
        """
        Callback called when our D-Bus bus owner changes 
        """
        if new_owner == '':
            logger.warning('No owner anymore for bus name ' + RemoteDhcpClientControl.DBUS_NAME)
            raise Exception('LostDhcpSlave')
        else:
            pass # Owner exists

    def _exitUnlock(self):
        """
        Callback used internally to unlock a timeout on exit
        """
        logger.debug('Unlocking exit()')
        self._exit_unlock_event.set()
        
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
        self._exit_unlock_event.clear()
        self._dbus_iface.Exit(reply_handler = self._exitUnlock, error_handler = self._exitUnlock) # Call Exit() but ignore whether it gets acknowledged or not... this is because slave process may terminate before even acknowledge
        self._exit_unlock_event.wait(timeout = 5) # Give 5s for slave to acknowledge the Exit() D-Bus method call... otherwise, ignore and continue
    
    def sendDiscover(self):
        logger.info('Instructing slave to send DISCOVER')
        self._dbus_iface.Discover() # Ask slave process to send a DHCP discover
    
    def getIpv4Address(self):
        """
        Get the current IPv4 address obtained by the DHCP client or None if we have no valid lease
        Returns it as string containing a dotted-decimal IPv4 address
        """
        with self.status_mutex:
            if self.status.ipv4_lease_valid is None:
                return None
            else:
                return self.status.ipv4_address
    
    def getIpv4Netmask(self):
        """
        Get the current IPv4 netmask obtained by the DHCP client or None if we have no valid lease
        Returns it as string containing a dotted-decimal IPv4 address
        """
        with self.status_mutex:
            if self.status.ipv4_lease_valid is None:
                return None
            else:
                return self.status.ipv4_netmask
            
    def getIpv4DefaultGateway(self):
        """
        Get the current IPv4 default gateway obtained by the DHCP client or None if we have no valid lease
        Returns it as string containing a dotted-decimal IPv4 address
        """
        with self.status_mutex:
            if self.status.ipv4_lease_valid is None:
                return None
            else:
                return self.status.ipv4_defaultgw

    def getIpv4DnsList(self):
        """
        Get the current list of IPv4 DNS obtained by the DHCP client or [None] if we have no valid lease
        Returns it as list of strings, each containing a dotted-decimal IPv4 address for each DNS server
        """
        with self.status_mutex:
            if self.status.ipv4_lease_valid is None:
                return [None]
            else:
                return self.status.ipv4_dnslist
            
    def isLeaseValid(self):
        """
        Is the current lease valid?
        """
        with self.status_mutex:
            return self.status.ipv4_lease_valid
                

class SlaveDhcpProcess:
    """
    Slave DHCP client process manipulation
    This class allows to run a DHCP client subprocess as root, and to terminate it
    dhcp_client_daemon_exec_path contains the name of the executable that implements the DHCP client
    ifname is the name of the network interface on which the DHCP client will run
    if log is set to False, no logging will be performed on the logger object 
    """
    
    def __init__(self, dhcp_client_daemon_exec_path, ifname, log = True):
        self._slave_dhcp_client_path = dhcp_client_daemon_exec_path
        self._slave_dhcp_client_proc = None
        self._slave_dhcp_client_pid = None
        self._ifname = ifname
        self._log = log
    
    def start(self):
        """
        Start the slave process
        """
        try:
            global all_processes_pid    # This process's list of child PIDs (global variable)
            cmd = ['sudo', self._slave_dhcp_client_path, '-i', self._ifname, '-A', '-S']
            logger.debug('Running command ' + str(cmd))
            self._slave_dhcp_client_proc = subprocess.Popen(cmd)#, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
            self._slave_dhcp_client_pid = self._slave_dhcp_client_proc.pid
            all_processes_pid += [self._slave_dhcp_client_proc.pid]
        except:
            raise   # Reraise exception exception handling
    
    def kill(self):
        """
        Stop the slave process
        """
        global all_processes_pid    # This process's list of child PIDs (global variable)
        if not self.isRunning():
            if self._log: logger.debug('Slave PID ' + str(self._slave_dhcp_client_pid) + ' has already terminated')
            while self._slave_dhcp_client_pid in all_processes_pid: all_processes_pid.remove(self._slave_dhcp_client_pid)   # Remove references to this child's PID in the list of children
        else:
            killSubprocessFromPid(self._slave_dhcp_client_pid)
            self._slave_dhcp_client_proc.wait()
        
        self._slave_dhcp_client_pid = None    
        self._slave_dhcp_client_proc = None

    def isRunning(self):
        """
        Is the child process currently running 
        """
        if not self.hasBeenStarted():
            return False
        
        return self._slave_dhcp_client_proc.poll()
    
    def hasBeenStarted(self):
        """
        Has the child process been started by us
        """
        return (not self._slave_dhcp_client_pid is None) and (not self._slave_dhcp_client_proc is None)
        
class DhcpClientLibrary:

    """ Robot Framework DHCP client Library """

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = '1.0'

    def __init__(self, dhcp_client_daemon_exec_path, ifname = None):
        """Initialise the library
        dhcp_client_daemon_exec_path is a PATH to the executable program that run the D-Bus controlled DHCP client (will be run as root via sudo)
        ifname is the interface on which we will act as a DHCP client. If not provided, it will be mandatory to set it using Set Interface and before running Start
        """
        self._dhcp_client_daemon_exec_path = dhcp_client_daemon_exec_path
        self._ifname = ifname
        self._slave_dhcp_process = None
        self._dhcp_client_ctrl = None    # Slave process not started
        self._new_lease_event = threading.Event() # At initialisation, event is cleared
        
    def set_interface(self, ifname):
        """Set the interface on which the DHCP client will act
        This must be done prior to calling Start on the DHCP client
        
        Example:
        | Set Interface | 'eth0' |
        """
        
        if not self._slave_dhcp_process is None:
            raise Exception('DhcpClientAlreadyStarted')
        
        self._ifname = ifname
        
    def get_interface(self, ifname):
        """Get the interface on which the DHCP client is configured to run (it may not be started yet)
        Will return None if no interface has been configured yet
        
        Example:
        | Set Interface | 'eth0' |
        | Get Interface |
        =>
        | 'eth0' |
        """
        
        return self._ifname

    def start(self):
        """Start the DHCP client
        
        Example:
        | Start |
        """
        
        if self._ifname is None:
            raise Exception('NoInterfaceProvided')
        self._slave_dhcp_process = SlaveDhcpProcess(self._dhcp_client_daemon_exec_path, self._ifname)
        self._slave_dhcp_process.start()
        self._new_lease_event.clear()
        self._dhcp_client_ctrl = RemoteDhcpClientControl()    # Create a RemoteDhcpClientControl object that symbolizes the control on the remote process (over D-Bus)
        self._dhcp_client_ctrl.notifyNewLease(self._got_new_lease)  # Ask underlying RemoteDhcpClientControl object to call self._new_lease_retrieved() as soon as we get a new lease 
        logger.debug('DHCP client started on ' + self._ifname)
        self._dhcp_client_ctrl.sendDiscover()
        
    def stop(self):
        """ Stop the DHCP client

        Example:
        | Stop |
        """

        if not self._dhcp_client_ctrl is None:
            self._dhcp_client_ctrl.exit()
        if not self._slave_dhcp_process is None:
            self._slave_dhcp_process.kill()
        self._new_lease_event.clear()
        self._slave_dhcp_process = None # Destroy the slave DHCP object
        logger.debug('DHCP client stopped on ' + self._ifname)
    
    def restart(self):
        """ Restart the DHCP client

        Example:
        | Restart |
        """

        self.stop()
        self.start()    
    
    def _got_new_lease(self):
        """
        Internal callback invoked when a new lease is allocated to the slave DHCP client
        """
        self._new_lease_event.set()
        
        
    def wait_lease(self, timeout = None, raise_exceptions = True):
        """ Alias for Wait Ipv4 Lease
        """
        return self.wait_ipv4_lease(timeout = timeout, raise_exceptions = raise_exceptions)
    
    def wait_ipv4_lease(self, timeout = None, raise_exceptions = True):
        """ Wait until we get a new lease (until timeout if specified)
        DHCP client starts as soon as Start keyword is called, so a lease may already be obtained when running keyword Wait Lease
        
        Return the IP address obtained
        
        Example:
        | Wait Ipv4 Lease |
        =>
        | ${ip_address} |
        """
        
        self._new_lease_event.wait(timeout = float(timeout))
        ipv4_address = self._dhcp_client_ctrl.getIpv4Address()
        if raise_exceptions and ipv4_address is None:
            raise Exception('DhcpLeaseTimeout')
        else:
            return unicode(ipv4_address)
        
    
    def get_address(self):
        """ Alias for Get Ipv4 Address
        """
        return self.get_ipv4_address()
    
    def get_ipv4_address(self):
        """ Get the IPv4 address for the current lease or ${None} if we have no currently valid lease
        
        Return the IPv4 address (as a string containing its dotted decimal notation, eg: '192.168.0.10')
        
        Example:
        | Get Ipv4 Address |
        =>
        | ${ip_address} |
        """
        
        ipv4_address = self._dhcp_client_ctrl.getIpv4Address()
        if ipv4_address is None:
            return None
        else:
            return unicode(ipv4_address)


    def get_netmask(self):
        """ Alias for Get Ipv4 Netmask
        """
        return self.get_ipv4_netmask()
    
    def get_ipv4_netmask(self):
        """ Get the IPv4 netmask for the current lease or ${None} if we have no currently valid lease
        
        Return the IPv4 netmask (as a string containing its dotted decimal notation, eg: '255.255.255.0'
        
        Example:
        | Get Ipv4 Netmask |
        =>
        | ${ip_netmask} |
        """
        
        ipv4_netmask = self._dhcp_client_ctrl.getIpv4Netmask()
        if ipv4_netmask is None:
            return None
        else:
            return unicode(ipv4_netmask)


    def get_defaultgw(self):
        """ Alias for Get Ipv4 DefaultGw
        """
        return self.get_ipv4_defaultgw()
    
    def get_ipv4_defaultgw(self):
        """ Get the IPv4 default gateway for the current lease or ${None} if we have no currently valid lease
        
        Return the IPv4 default gateway (as a string containing its dotted decimal notation, eg: '192.168.0.1'
        
        Example:
        | Get Ipv4 DefaultGw |
        =>
        | ${ip_defaultgw} |
        """
        
        ipv4_defaultgw = self._dhcp_client_ctrl.getIpv4DefaultGateway()
        if ipv4_defaultgw is None:
            return None
        else:
            return unicode(ipv4_defaultgw)
    
    
    def is_lease_valid(self):
        """ Alias for Is Ipv4 Lease Valid
        """
        return self.is_ipv4_lease_valid()
    
    def is_ipv4_lease_valid(self):
        """ Check if we currently have a valid lease
        
        Example:
        | Is Ipv4 Lease Valid |
        =>
        | ${True} |
        """
        
        return self._dhcp_client_ctrl.isLeaseValid()
    

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)    # Use Glib's mainloop as the default loop for all subsequent code

if __name__ == '__main__':
    atexit.register(cleanupAtExit)
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
    print("Waiting 10s to get a DHCP lease")
    ip_addr = client.wait_lease('10')
    print("Got a lease with IP address " + ip_addr)
    input('Press enter to stop slave')
    client.stop()
    #assert IP == client.get_ip(MAC, '_http._tcp')
    #DATA = BL.check_run(IP, '_http._tcp')
    #BL.get_apname(DATA)
    #input('Press enter & "Disable UPnP/Bonjour" on web interface')
    #BL.check_stop(IP, '_http._tcp')
else:
    from robot.api import logger

