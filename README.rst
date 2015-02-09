DhcpClientLibrary for Robot Framework
=====================================

Introduction
------------

DhcpClientLibrary is a `Robot Framework <http://robotframework.org>`__ test
library for testing a DHCP server.

This library allows Robot Framework to interact with a DHCP server and to
handle DHCP events using Robot Framework keywords

DhcpClientLibrary is open source software licensed under `Apache License 2.0
<http://www.apache.org/licenses/LICENSE-2.0.html>`__.

Installation
------------

First, install the forked version pydhcplib available
`here<https://github.com/Legrandgroup/pydhcplib>`__.
We cannot use the standard pydhcplib because we need to be able to specify
the network interface on which we run the DHCP client.

Once pydhcplib is installed, run the ./setup.py script.
