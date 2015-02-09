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

### Setting the D-Bus permissions

In order to allow the D-Bus messages used by DhcpClientLibrary (on the system bus),
you will need to setup the permissions accordingly.

Here is a sample permission file to save in /etc/d-bus-1/system.d:

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
  It is remotely controlled by D-Bus method invokations.
  It reports DHCP states by sending D-Bus signals.
  This module is imported by RobotFramework but can also be run stand-alone (in that cas, it
  behaves as a DHCP client)
* [DhcpClientLibrary.py](DhcpClientLibrary.py): This is the RobotFramework library.
  Its primary class is DhcpClientLibrary
  This Python code runs within the RobotFramework process, with the same access rights as
  RobottFramework.
  It will run a child subrocess that will execute `DBusControlledDhcpClient.py` as root (via sudo).
  It will then interact with this subprocess using D-Bus calls & signals.
  It offers a RobotFramework interface to allow the use of higher level RobotFramework keywords.

These 2 processes are communicating via the D-Bus SYSTEM bus, under the object path
/com/legrandelectric/RobotFrameworkIPC/*interface* , where *interface* corresponds to the
network interface name on which the DHCP client runs (eg: *eth1*)

This D-Bus object implements a service interface called
`com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary`
Its properties and the interprocessus communication looks like:
![robotframework-dhcpclientlibrary architecture](/img/rfdhcpclientlib-arch.png?raw=true "robotframework-dhcpclientlibrary architecture")
