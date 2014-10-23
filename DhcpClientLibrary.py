#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

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

import DhcpLeaseStatus

import tempfile # Temporary to debug TimeoutOnGetVersion

client = None

# This cleanup handler is not used when this library is imported in RF, only when run as standalone
if __name__ == '__main__':
    def cleanupAtExit():
        """
        Called when this program is terminated, to perform the same cleanup as expected in Teardown when run within Robotframework
        """
        
        global client
        
        client.stop()

    

def catchall_signal_handler(*args, **kwargs):
    """
    Function used for debugging D-Bus signals only
    """ 
    print("Caught signal (in catchall handler) " + kwargs['dbus_interface'] + "." + kwargs['member'])
    for arg in args:
        print("        " + str(arg))


class RemoteDhcpClientControl:

    """
    DHCP client object representing a remote (slave) DHCP client process
    This slave process must already be running (we won't launch it ourselves)
    Will will communicate with this slave using D-Bus Methods and catch the D-Bus signals it emits
    """

    DBUS_NAME = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'    # The name of bus we are connecting to on D-Bus
    DBUS_OBJECT_ROOT = '/com/legrandelectric/RobotFrameworkIPC/DhcpClientLibrary'    # The name of the D-Bus object under which we will communicate on D-Bus
    DBUS_SERVICE_INTERFACE = 'com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary'    # The name of the D-Bus service under which we will perform input/output on D-Bus

    def __init__(self, ifname):
        """
        Instantiate a new RemoteDhcpClientControl object that represents a DHCP client remotely-controlled via D-Bus
        This RemoteDhcpClientControl object will mimic the status/methods of the remotely-controlled DHCP client so that we can interact with RemoteDhcpClientControl without any knowledge of the actual remotely-controller DHCP client
        """

        self._dbus_loop = gobject.MainLoop()
        self._bus = dbus.SystemBus()
        wait_bus_owner_timeout = 5  # Wait for 5s to have an owner for the bus name we are expecting
        logger.debug('Going to wait for an owner on bus name ' + RemoteDhcpClientControl.DBUS_NAME)
        while not self._bus.name_has_owner(RemoteDhcpClientControl.DBUS_NAME):
            time.sleep(0.2)
            wait_bus_owner_timeout -= 0.2
            if wait_bus_owner_timeout <= 0: # We timeout without having an owner for the expected bus name
                raise Exception('No owner found for bus name ' + RemoteDhcpClientControl.DBUS_NAME)
        
        logger.debug('Got an owner for bus name ' + RemoteDhcpClientControl.DBUS_NAME)
        gobject.threads_init()    # Allow the mainloop to run as an independent thread
        dbus.mainloop.glib.threads_init()
        
        dbus_object_name = RemoteDhcpClientControl.DBUS_OBJECT_ROOT + '/' + str(ifname)
        logger.debug('Going to communicate with object ' + dbus_object_name)
        self._dhcp_client_proxy = self._bus.get_object(RemoteDhcpClientControl.DBUS_SERVICE_INTERFACE, dbus_object_name)
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

        self.status = DhcpLeaseStatus.DhcpLeaseStatus()

        self._getversion_unlock_event.clear()
        self._remote_version = ''
        self._dbus_iface.GetVersion(reply_handler = self._getVersionUnlock, error_handler = self._getVersionError)
        if not self._getversion_unlock_event.wait(10):   # We give 10s for slave to answer the GetVersion() request
            logfile = tempfile.NamedTemporaryFile(prefix='TimeoutOnGetVersion-', suffix='.log', delete=False)
            if logfile:
                print('Saving TimeoutOnGetVersion environment dump to file "' + logfile.name + '"', file=sys.stderr)
                print('TimeoutOnGetVersion', file=logfile)
                subprocess.call('ps -ef', stdout=logfile, shell=True)
                subprocess.call('perl ./dbus-introspect.pl --system com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary /com/legrandelectric/RobotFrameworkIPC/DhcpClientLibrary/eth1', stdout=logfile, shell=True)
                subprocess.call('dbus-send --system --type=method_call --print-reply --dest=com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary /com/legrandelectric/RobotFrameworkIPC/DhcpClientLibrary/eth1 com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary.GetVersion', stdout=logfile, shell=True)
                logfile.close()
            raise Exception('TimeoutOnGetVersion')
        else:
            logger.debug('Slave version: ' + self._remote_version)        
        
    # D-Bus-related methods
    def getRemotePid(self):
        return self._dbus_iface.GetPid()
    
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
            with self.status._dhcp_status_mutex:
                if self.status.ipv4_lease_valid:
                    callback()  # Call callback function right now if lease is already valid
                else:   # We still hold the mutex here because we don't want ipv4_lease_valid to be changed before we install the callback ;-)
                    with self._callback_new_lease_mutex:
                        self._callback_new_lease = callback
    
    def _handleIpConfigApplied(self, interface, ip, netmask, defaultgw, leasetime, dns_space_sep, serverid, **kwargs):
        """
        Method called when receiving the IpConfigApplied signal from the slave process
        """
        logger.debug('Got signal IpConfigApplied')
        with self.status._dhcp_status_mutex:
            self.status.ipv4_address = ip
            self.status.ipv4_netmask = netmask
            self.status.ipv4_defaultgw = defaultgw
            self.status.ipv4_dhcpserverid = serverid
            self.status.ipv4_lease_valid = True
            self.status.ipv4_lease_duration = leasetime
            self.status.ipv4_lease_expiry = datetime.datetime.now() + datetime.timedelta(seconds = int(leasetime))    # Calculate the time when the lease will expire
            logger.debug('Lease obtained for IP: ' + ip + '. Will expire at ' + str(self.status.ipv4_lease_expiry))
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
            logger.warn('No owner anymore for bus name ' + RemoteDhcpClientControl.DBUS_NAME)
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
        Terminate the D-Bus control over the remote client
        This will also ask the remote (via D-Bus) to send a Release message
        """
        if self._dbus_iface is None:
            raise Exception('Method invoked on non existing D-Bus interface')
        self._dbus_iface.Release(reply_handler = self._exitUnlock, error_handler = self._exitUnlock) # Call Exit() but ignore whether it gets acknowledged or not... this is because slave process may terminate before even acknowledge
        self._exit_unlock_event.wait(timeout = 5) # Give 5s for slave to acknowledge the Exit() D-Bus method call... otherwise, ignore and continue
        # Once we have instructed the slave to send a Release, we can stop our own D-Bus loop (we won't communicate with the slave anymore)
        # Stop the dbus loop
        if not self._dbus_loop is None:
            self._dbus_loop.quit()
        
        self._dbus_loop = None
        
        logger.debug('Sending Exit() to remote DHCP client')
        self._exit_unlock_event.clear()
    
    def sendDiscover(self):
        logger.info('Instructing slave to send DISCOVER')
        self._dbus_iface.Discover() # Ask slave process to send a DHCP discover
    
    def getIpv4Address(self):
        """
        Get the current IPv4 address obtained by the DHCP client or None if we have no valid lease
        Returns it as string containing a dotted-decimal IPv4 address
        """
        with self.status._dhcp_status_mutex:
            if self.status.ipv4_lease_valid is None:
                return None
            else:
                return self.status.ipv4_address
    
    def getIpv4Netmask(self):
        """
        Get the current IPv4 netmask obtained by the DHCP client or None if we have no valid lease
        Returns it as string containing a dotted-decimal IPv4 address
        """
        with self.status._dhcp_status_mutex:
            if self.status.ipv4_lease_valid is None:
                return None
            else:
                return self.status.ipv4_netmask
            
    def getIpv4DefaultGateway(self):
        """
        Get the current IPv4 default gateway obtained by the DHCP client or None if we have no valid lease
        Returns it as string containing a dotted-decimal IPv4 address
        """
        with self.status._dhcp_status_mutex:
            if self.status.ipv4_lease_valid is None:
                return None
            else:
                return self.status.ipv4_defaultgw

    def getIpv4DnsList(self):
        """
        Get the current list of IPv4 DNS obtained by the DHCP client or [None] if we have no valid lease
        Returns it as list of strings, each containing a dotted-decimal IPv4 address for each DNS server
        """
        with self.status._dhcp_status_mutex:
            if self.status.ipv4_lease_valid is None:
                return [None]
            else:
                return self.status.ipv4_dnslist
            
    def getIpv4DhcpServerId(self):
        """
        Get the current IPv4 DHCP server ID gateway obtained by the DHCP client or None if we have no valid lease
        Returns it as string containing a dotted-decimal IPv4 address
        """
        with self.status._dhcp_status_mutex:
            if self.status.ipv4_lease_valid is None:
                return None
            else:
                return self.status.ipv4_dhcpserverid
            
            
    def isLeaseValid(self):
        """
        Is the current lease valid?
        """
        with self.status._dhcp_status_mutex:
            return self.status.ipv4_lease_valid
                

class SlaveDhcpClientProcess:
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
        self._all_processes_pid = []  # List of all subprocessed launched by us
    
    def start(self):
        """
        Start the slave process
        """
        if self.isRunning():
            raise Exception('DhcpClientAlreadyStarted')
        cmd = ['sudo', self._slave_dhcp_client_path, '-i', self._ifname, '-A', '-S']
        logger.debug('Running command ' + str(cmd))
        #self._slave_dhcp_client_proc = robot.libraries.Process.Process()
        #self._slave_dhcp_client_proc.start_process('sudo', self._slave_dhcp_client_path, '-i', self._ifname, '-A', '-S')
        self._slave_dhcp_client_proc = subprocess.Popen(cmd)#, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
        self._slave_dhcp_client_pid = self._slave_dhcp_client_proc.pid
        self.addSlavePid(self._slave_dhcp_client_proc.pid) # Add the PID of the child to the list of subprocesses (note: we get sudo's PID here, not the slave PID, that we will get later on via D-Bus (see RemoteDhcpClientControl.getPid())
        
    def addSlavePid(self, pid):
        """
        Add a (child) PID to the list of PIDs that we should terminate when kill() is run
        """
        logger.debug('Adding slave PID ' + str(pid))
        if not pid in self._all_processes_pid:  # Make sure we don't add twice a PID
            self._all_processes_pid += [pid] # Add

    def _checkPid(self, pid):        
        """
        Check For the existence of a UNIX PID
        """
        
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True
    
    def _sudoKillSubprocessFromPid(self, pid, log = True, force = False, timeout = 1):
        """
        Kill a process from it PID (first send a SIGINT)
        If argument force is set to True, wait a maximum of timeout seconds after SIGINT and send a SIGKILL if is still alive after this timeout
        """

        if log: logger.info('Sending SIGINT to slave PID ' + str(pid))
        args = ['sudo', 'kill', '-SIGINT', str(pid)]    # Send Ctrl+C to slave DHCP client process
        subprocess.call(args, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
        
        if force:
            while self._checkPid(pid):  # Loop if slave process is still running
                time.sleep(0.1)
                timeout -= 0.1
                if timeout <= 0:    # We have reached timeout... send a SIGKILL to the slave process to force termination
                    if log: logger.info('Sending SIGKILL to slave PID ' + str(pid))
                    args = ['sudo', 'kill', '-SIGKILL', str(pid)]    # Send Ctrl+C to slave DHCP client process
                    subprocess.call(args, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
                    break

    def killSlavePids(self):
        """
        Stop all PIDs stored in the list self._all_processes_pid
        This list actually contains the list of all recorded slave processes' PIDs
        """
        for pid in self._all_processes_pid:
            self._sudoKillSubprocessFromPid(pid)
            # The code below is commented out, we will just wipe out the whole  self._all_processes_pid[] list below
            #while pid in self._all_processes_pid: self._all_processes_pid.remove(pid)   # Remove references to this child's PID in the list of children
        if not self._slave_dhcp_client_proc is None:
            self._slave_dhcp_client_proc.wait() # Wait for sudo child (our only direct child)
        
        self._all_processes_pid = []    # Empty our list of PIDs
        
        self._slave_dhcp_client_pid = None    
        self._slave_dhcp_client_proc = None

    def kill(self):
        """
        Stop the slave process(es)
        """
        
        self.killSlavePids()
        
    def isRunning(self):
        """
        Is/Are the child process(es) currently running 
        """
        if not self.hasBeenStarted():
            return False
        
        if not self._slave_dhcp_client_proc.poll(): # Poll our direct child (sudo)
            return False
        
        for pid in self._all_processes_pid:
            if not self._checkPid(pid):
                return False
        
        return True
    
    def hasBeenStarted(self):
        """
        Has the child process been started by us
        """
        return (not self._slave_dhcp_client_pid is None) and (not self._slave_dhcp_client_proc is None)
        
        
class DhcpClientLibrary:
    """Robot Framework DHCP client Library

    This library utilizes Python's
    [http://docs.python.org/2.7/library/subprocess.html|subprocess]
    module and dbus-python [http://dbus.freedesktop.org/doc/dbus-python/doc/tutorial.html]
    as well as the Python module [https://docs.python.org/2.7/library/signal.html]
    
    The library has following usage:

    - Running a DHCP client on a specific network interface and interact with
      the DHCP client to instruct it to perform some DHCP actions (DISCOVER,
      RENEW, RELEASE) or to get informations of the DHCP state machine
      (current IP address, netmask, DNS, lease duration etc...) 

    == Table of contents ==

    - `Requirement on the test machine`
    - `Specifying environment to the library`
    - `Requirements for Setup/Teardown`

    = Requirement on the test machine =
    
    A few checks must be performed on the machine on which this library will
    run :
    - The D-Bus system bus must have appropriate permissions to allow messages
    on the BUS `com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary`.
    For example, the following lines in a file stored in /etc/d-bus-1/system.d
    would do the job (but you may want to setup more restrictive permissions):
    <!DOCTYPE busconfig PUBLIC
    "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
    "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
    <busconfig>
      <policy context="default">
        <allow own="com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary"/>
        <allow send_destination="com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary"/>
      </policy>
    </busconfig>
    
    - The pybot process must have permissions to run sudo on kill and on
    the slave DHCP python process (DBusControlledDhcpClient.py)  
    
    = Specifying environment to the library =
    
    Before being able to run a DHCP client on an interface, this library must
    be provided with the path to the DHCP client exec (also called slave
    in this library) that will perform the actual DHCP packet send/receive.
    This exec should point to DBusControlledDhcpClient.py (executable Python
    program provided with this library)
    
    Also, the network interface on which the DHCP client service will run
    must be provided either :
    - when importing the library with the keyword `Library` 
    - by using the keyword `Set Interface` before using the keyword `Start`
    - by providing it as an optional argument when using the keyword `Start`
    
    
    = Requirements for Setup/Teardown =

    Whenever `DhcpClientLibrary.Start` is run within a given scope, it is
    mandatory to make sure than `DhcpClientLibrary.Stop` will also be called
    before or at Teardown to avoid runaway DHCP client processes (namely
    DBusControlledDhcpClient.py)
    

    = Example =

    | ***** Settings *****
    | Library    DhcpClientLibrary    DBusControlledDhcpClient.py
    | Suite Setup    `DhcpClientLibrary.Start`   eth1
    | Suite Teardown    `DhcpClientLibrary.Stop`
    |
    | ***** Test Cases *****
    | Example
    |     `DhcpClientLibrary.Set Interface`    eth1
    |     `DhcpClientLibrary.Wait Lease`     5
    |     ${temp_scalar}=    `DhcpClientLibrary.Get Ipv4 Defaultgw`
    """

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROBOT_LIBRARY_VERSION = '1.0'

    def __init__(self, dhcp_client_daemon_exec_path, ifname = None):
        """Initialise the library
        dhcp_client_daemon_exec_path is a PATH to the executable program that run the D-Bus controlled DHCP client (will be run as root via sudo)
        ifname is the interface on which we will act as a DHCP client. If not provided, it will be mandatory to set it using Set Interface and before (or when) running Start
        """
        self._dhcp_client_daemon_exec_path = dhcp_client_daemon_exec_path
        self._ifname = ifname
        self._slave_dhcp_process = None
        self._dhcp_client_ctrl = None    # Slave DHCP client process not started
        self._new_lease_event = threading.Event() # At initialisation, event is cleared
        
    def set_interface(self, ifname):
        """Set the interface on which the DHCP client will act
        This must be done prior (or when) the Start keyword is called or subsequent actions will fail
        
        Example:
        | Set Interface | eth0 |
        """
        
        if not self._slave_dhcp_process is None:
            raise Exception('DhcpClientAlreadyStarted')
        
        self._ifname = ifname
        
    def get_interface(self, ifname):
        """Get the interface on which the DHCP client is configured to run (it may not be started yet)
        Will return None if no interface has been configured yet
        
        Example:
        | Set Interface | eth0 |
        | Get Interface |
        =>
        | 'eth0' |
        """
        
        return self._ifname

    def start(self, ifname = None):
        """Start the DHCP client
        
        Example:
        | Start | eth1 |
        """
        
        if not self._slave_dhcp_process is None:
            raise Exception('DhcpClientAlreadyStarted')
        
        if not ifname is None:
             self._ifname = ifname
        
        if self._ifname is None:
            raise Exception('NoInterfaceProvided')
        
        self._slave_dhcp_process = SlaveDhcpClientProcess(self._dhcp_client_daemon_exec_path, self._ifname)
        self._slave_dhcp_process.start()
        self._new_lease_event.clear()
        self._dhcp_client_ctrl = RemoteDhcpClientControl(self._ifname)    # Create a RemoteDhcpClientControl object that symbolizes the control on the remote process (over D-Bus)
        self._dhcp_client_ctrl.notifyNewLease(self._got_new_lease)  # Ask underlying RemoteDhcpClientControl object to call self._new_lease_retrieved() as soon as we get a new lease 
        logger.debug('DHCP client started on ' + self._ifname)
        slave_pid = self._dhcp_client_ctrl.getRemotePid()
        if slave_pid is None:
            logger.error('Could not get remote process PID')
            raise('RemoteCommunicationError')
        else:
            logger.debug('Slave has PID ' + str(slave_pid))        
            self._slave_dhcp_process.addSlavePid(slave_pid)

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
            logger.debug('DHCP client stopped on ' + self._ifname)
        
        self._new_lease_event.clear()
        self._dhcp_client_ctrl = None   # Destroy the control object
        self._slave_dhcp_process = None # Destroy the slave DHCP object
        
    
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
    
        
    def get_serverid(self):
        """ Alias for Get Ipv4 Serverid
        """
        return self.get_ipv4_serverid()
    
    def get_ipv4_serverid(self):
        """ Get the IPv4 default gateway for the current lease or ${None} if we have no currently valid lease
        
        Return the IPv4 default gateway (as a string containing its dotted decimal notation, eg: '192.168.0.1'
        
        Example:
        | Get Ipv4 Serverid |
        =>
        | ${ipv4_serverid} |
        """
        
        ipv4_serverid = self._dhcp_client_ctrl.getIpv4DhcpServerId()
        if ipv4_serverid is None:
            return None
        else:
            return unicode(ipv4_serverid)
        
        
    def get_dns_list(self):
        """ Alias for Get Ipv4 Dns List
        """
        return self.get_ipv4_dns_list()
    
    def get_ipv4_dns_list(self):
        """ Get the IPv4 dns list for the current lease or [${None}] if we have no currently valid lease
        
        Return the IPv4 default gateway (as a list containing one entry per DNS server, each entry being a string with a dotted decimal notation, eg: '192.168.0.1')
        
        Example:
        | Get Ipv4 Dns List |
        =>
        | ${ip_dns_list} |
        """
        
        ipv4_dns_list = self._dhcp_client_ctrl.getIpv4DnsList()
        if ipv4_dns_list is None:
            return [None]
        else:
            return map(unicode, ipv4_dns_list)
        
        
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
else:
    from robot.api import logger

