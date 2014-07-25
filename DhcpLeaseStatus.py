# -*- coding: utf-8 -*-

import threading

class DhcpLeaseStatus:
    """
    This object represents a DHCP lease status database
    Note: all IPv4 address stored here should be done using type str
    Exceptions to this is:
    - ipv4_lease_valid is of type boolean
    - ipv4_lease_duration is of type int (representing a duration in seconds)
    - ipv4_lease_remaining is of type int (representing a duration in seconds)
    - ipv4_lease_expiry is of type time.struct_time object
    """

    def __init__(self):
        self._dhcp_status_mutex = threading.RLock()    # This re-intrant mutex protects writes to any of the variables of this object
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
            if not self.ipv4_lease_duration is None:
                temp += 'IPv4 lease last for: ' + str(self.ipv4_lease_duration) + 's\n'
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
            self.ipv4_lease_duration = None  # How long the lease lasts
            #self.ipv4_lease_remaining   # For how long the lease is still valid?
            self.ipv4_lease_expiry = None    # When the lease will expire (in UTC time), as a time.struct_time object



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
