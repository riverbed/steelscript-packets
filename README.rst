Riverbed SteelScript Packets
=================================================

This package provides Cython extensions for python to assist in parsing
PCAP and PCAPNG files. It also includes a library of basic internet packet
types including Ethernet, IP, TCP, UDP, ARP, and others.

For a complete guide to installation, see:

  `https://support.riverbed.com/apis/steelscript/index.html <https://support.riverbed.com/apis/steelscript/index.html>`_

License
=======

Copyright (c) 2019 Riverbed Technology, Inc.

SteelScript-Packets is licensed under the terms and conditions of the MIT
License accompanying the software ("License").  SteelScript-Packets is
distributed "AS IS" as set forth in the License.

Install steelscript.packets:
============================

These installation instructions assume you already have a functioning python 3.6 or 3.7 environment on your machine.

Requirements:

1. Python3.6-3.7
2. Development tools for your OS
3. steelscript
4. Cython
5. libpcap headers. See note below on installing libpcap on MacOS and Linux.

Steps:

1. Install development tools and libpcap as shown below.
2. $ pip install Cython
3. $ pip install steelscript
4. $ pip install steelscript.packets


Notes on installing development tools and libpcap on MacOS and Linux:

:MacOS:

::

  Installing the development environment is a matter of installing Xcode and
  then installing the Xcode command line tools

  The simplest way to get these headers installed is to use HomeBrew or
  MacPorts.
  $ sudo homebrew install lippcap
  or
  $ sudo port install libpcap

:Linux (Debian based):

::

  The meta package name for the base development tools is usually called
  ‘build-essential’ so the following command should get everything you
  need:
  $ sudo apt-get install libpcap-dev build-essential

:Linux (RedHat based):

::

  The meta package name (group name) on RedHat based systems is usually
  ‘Development Tools” The following commands should get everything you need
  installed.
  $ sudo yum group install "Development Tools"
  $ sudo yum install libpcap-devel

  It is possible your yum config may have optional groups disabled. If the
  "Development Tools" install fails then simply add
  ‘--setopt=group_package_types=mandatory,default,optional’ to your yum
  command.