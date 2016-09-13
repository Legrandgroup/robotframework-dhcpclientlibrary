DhcpClientLibrary for Robot Framework
=====================================


## Introduction

DhcpClientLibrary is a [Robot Framework](http://robotframework.org) test
library for testing a DHCP server. It will send/receive DHCP packets to a server in
order to stimulate this server (you can also send out of sequence requests from
within this library if needed).
In order to bind to a specific interface, we need to run the DHCP client code as
root so you will need to setup sudo accordingly (see below for more on this topic)

This library allows Robot Framework to interact with a DHCP server and to
handle DHCP events using Robot Framework keywords

Currently, it only supports IPv4 DHCP (not IPv6)

DhcpClientLibrary is open source software licensed under
[Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0.html).

## For users

### Installation

First, install the forked version pydhcplib available
[here](https://github.com/Legrandgroup/pydhcplib).
Note: pydhcplib is available, for example, in Debian wheezy under the package
python-pydhcplib, but we cannot use this standard pydhcplib because we need to be
able to specify the network interface on which we run the DHCP client.

You can also install the locally modified version of pydhcplib in a local
directory (in order note to interfere with an official version of pydhcplib).
In order to do this, just add the --prefix= option when running pydhcplib's
`./setup.py install` command.

If you decice to go that way, you will have to fix the search PATH yourself though,
so that the RobotFramework DhcpClientLibrary uses the correct pydhcplib version.
You can either:
- use the environment variable PYTHONPATH
- or modify rfdhcpclientlib/DhcpClientLibrary.py as follows:
```python
import sys
sys.path.insert(0, '/opt/python-local/lib/python2.7/site-packages/') # Insert this line, adapting the path to your local setup
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *
```

Once this library is installed, you can use it with the following python import:
import rfdhcpclientlib.DhcpClientLibrary

### Setting the D-Bus permissions

In order to allow the D-Bus messages used by DhcpClientLibrary (on the system bus),
you will need to setup the permissions accordingly.

Here is a sample permission file to save in /etc/dbus-1/system.d:

```XML
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy context="default">
    <allow own="com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary"/>
    <allow send_destination="com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary"/>
  </policy>
</busconfig>
```

### Robot Framework keywords

The following RobotFramework keywords are made available by this library:
Note: it is advised to go directly inside the python code's docstrings (or via
RIDE's online help) to get a detailed description of keywords).

#### `Start`

*Start the DHCP client*

Note: a network interface must be either:
* have been provided using **`Set Interface`** prior to calling **`Start`**
* be provided as an argument to **`Start`**

#### `Stop`
*Stop the DHCP client subprocess*

Warning: It is really mandatory to call **`Stop`** each time **`Start`** is
called, or zombie subprocesses may be hanging around forever. Thus, the best
is to take the habit to use **`Stop`** in the teardown (in case a test fails)

#### `Restart`
*Equivalent to `Start`+`Stop`*

#### `Set Interface`
*Set the network interface on which the DHCP client runs*

eg: `eth1`

#### `Get Interface`
*Get the network interface on which the DHCP client runs*

#### `Wait Ipv4 Lease`
*Wait for a DHCP lease*

A timeout can be setup if needed.
The IP address allocated by the DHCP server is returned

#### `Get Ipv4 Address`
*Get the IPv4 address currently allocated to the DHCP client*

#### `Get Ipv4 Netmask`
*Get the current IPv4 netmask*

Format is dotted-decimal

#### `Get Ipv4 Defaultgw`
*Get the current IPv4 default gateway*

#### `Get Ipv4 Serverid`
*Get the IPv4 address of the DHCP server*

This IPv4 address corresponds to the DHCP server that allocated a lease to us

#### `Get Ipv4 Dns List`
*Get the list of IPv4 DNS provided by the DHCP server*

#### `Is Ipv4 Lease Valid`
*Does the DHCP client currently has a lease*

Returns `${True}` for a valid (non-expired) lease

## For developpers

### Architecture of DhcpClientLibrary

Having a working Python DHCP client requires root access rights in order to bind
on a specific interface.

RobotFramework usually does not execute with root access rigths, so the library is split between
two distinct processes:

* [DBusControlledDhcpClient.py](/scripts/DBusControlledDhcpClient.py): A Python DHCP client
  handler.
  Its primary class is DBusControlledDhcpClient
  This code is running in a process that is distinct from RobotFramework, with root access rights.
  It sends/receives DHCP packets directly on a network interface (via the pydhcplib library).
  It is remotely controlled by D-Bus method invokations (it publishes a D-Bus service)
  It reports DHCP states by sending D-Bus signals.
  This module is imported by RobotFramework but can also be run stand-alone (in that cas, it
  behaves as a DHCP client)
* [DhcpClientLibrary.py](/rfdhcpclientlib/DhcpClientLibrary.py): This is the RobotFramework library.
  Its primary class is DhcpClientLibrary
  This Python code runs within the RobotFramework process, with the same access rights as
  RobottFramework.
  It will run a child subrocess that will execute `DBusControlledDhcpClient.py` as root (via sudo).
  It will then interact with this subprocess using D-Bus calls & signals (it is a D-Bus client of
  `DBusControlledDhcpClient.py`)
  It offers a RobotFramework interface to allow the use of higher level RobotFramework keywords.

These 2 processes are communicating via the D-Bus SYSTEM bus, under the object path
/com/legrandelectric/RobotFrameworkIPC/*interface* , where *interface* corresponds to the
network interface name on which the DHCP client runs (eg: *eth1*)

This D-Bus object implements a service interface called
`com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary`
Its properties and the interprocessus communication looks like:
![robotframework-dhcpclientlibrary architecture](/img/rfdhcpclientlib-arch.svg?raw=true "robotframework-dhcpclientlibrary architecture")

### D-Bus messaging used between `DBusControlledDhcpClient` and `DhcpClientLibrary`

The following D-Bus signals are sent by `DBusControlledDhcpClient.py`:

* `DhcpDiscoverSent` when a DHCP Discover packet is sent to the network
* `DhcpOfferRecv` when a DHCP Offer packet is received from the network
* `DhcpRequestSent` when a DHCP Request packet is sent to the network in order to request an
  IP address lease
* `DhcpRenewSent`  when a DHCP Request packet is sent to the network in order to renew a
  an existing lease
* `DhcpReleaseSent` when a IP address lease is released (and it is also sent when the processus
  running DBusControlledDhcpClient.py is terminated)
* `DhcpAckRecv` when a DHCP Ack packet is received from the network
* `IpConfigApplied` when an IP configuration is acknowledged by the DHCP server. This signal also
  contains details about the lease (as string arguments: IP address, netmask, default gateway and
  the DNS servers (space-separated list in a string)
* `IpDnsReceived` when a DNS server list is acknowledged by the DHCP server. This signal also
  contains on string argument: a space-separated list of the DNS servers
* `LeaseLost` when the current IP address lease is lost

The following D-Bus methods can be invoked on `DBusControlledDhcpClient.py`:

* `Discover()`: (re)start the IP address discovery. This is done automatically when
  `DBusControlledDhcpClient.py` is run in standalone mode, but must be done manually when one
  creates an instance of a `DBusControlledDhcpClient` object. On usually invokes the
  `sendDhcpDiscover()` method, which is equivalent but not available via D-Bus
* `GetVersion()`: Get the version of the currently running `DBusControlledDhcpClient.py`
* `GetInterface()`: Get the network interface on which `DBusControlledDhcpClient.py` runs
* `GetPid()`: Returns an integer containing the PID of the process running
  `DBusControlledDhcpClient.py`
* `Renew()`: force renewing the DHCP lease immediately
* `Restart()`: restart the DHCP client (Release + restart from Discover stage)
* `FreezeRenew()`: prevent any renew of the DHCP lease (but do not send a DHCP Release either)
* `Debug()`: Write to stdout the character string provided as parameter

### D-Bus diagnosis using D-Feet

It is possible du trace D-Bus messages sent on interface
`com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary`

* In order to follow the state machine during executing of RobotFramework (by tracing D-Bus
  messages between DBusControlledDhcpClient and DhcpClientLibrary)
* When manually running `DBusControlledDhcpClient`, in order to control it via D-Bus (there
  will also be some debug information on the console)

To trace D-Bus messages, you can use D-Feet for Gnome, selecting the system bus, and interface
`com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary`

![Debugging using D-Feet](/img/debug-using-D-Feet.png?raw=true "Debugging using D-Feet")

You can then invoke D-Bus methods on the `DBusControlledDhcpClient.py` process.

