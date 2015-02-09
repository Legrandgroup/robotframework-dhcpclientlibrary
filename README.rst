DhcpClientLibrary for Robot Framework
=====================================

Introduction
------------

DhcpClientLibrary is a `Robot Framework <http://robotframework.org>`__ test
library for testing a DHCP server. It will send/receive DHCP packets to a server in
order to stimulate this server (you can also send out of sequence requests from
within this library if needed).
In order to bind to a specific interface, we need to run the DHCP client code as
root so you will need to setup sudo accordingly (see below for more on this topic)

This library allows Robot Framework to interact with a DHCP server and to
handle DHCP events using Robot Framework keywords

DhcpClientLibrary is open source software licensed under `Apache License 2.0
<http://www.apache.org/licenses/LICENSE-2.0.html>`__.

Installation
------------

First, install the forked version pydhcplib available
`here <https://github.com/Legrandgroup/pydhcplib>`__.
Note: pydhcplib is available, for example, in Debian wheezy under the package
python-pydhcplib, but we cannot use this standard pydhcplib because we need to be
able to specify the network interface on which we run the DHCP client.

You can also install the locally modified version of pydhcplib in a local
directory (in order note to interfere with an official version of pydhcplib).
In order to do this, just add the --prefix= option when running pydhcplib's
"./setup.py install" command.

If you decice to go that way, you will have to fix the search PATH yourself though,
so that the RobotFramework DhcpClientLibrary uses the correct pydhcplib version.
You can either:
- use the environment variable PYTHONPATH
- or modify rfdhcpclientlib/DhcpClientLibrary.py as follows:
import sys
sys.path.insert(0, '/opt/python-local/lib/python2.7/site-packages/') # Insert this line, adapting the path to your local setup
from pydhcplib.dhcp_packet import *
from pydhcplib.dhcp_network import *

Fixing the D-Bus permissions
----------------------------

In order to allow the D-Bus messages used by DhcpClientLibrary (on the system bus),
you will need to setup the permissions accordingly.

Here is a sample permission file to save in /etc/d-bus-1/system.d:

    <!DOCTYPE busconfig PUBLIC
     "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
     "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
    <busconfig>
      <policy context="default">
        <allow own="com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary"/>
        <allow send_destination="com.legrandelectric.RobotFrameworkIPC.DhcpClientLibrary"/>
      </policy>
    </busconfig>


Architecture of DhcpClientLibrary
---------------------------------

having a working Python DHCP client requires root access rights in order to bind
on a specific interface.
