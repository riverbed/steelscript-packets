# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""
steelscript.packets
====================
Cython implemented classes for reading and, in most cases writing pcap, pcapng
Ethernet, IP, TCP, and UDP. Plus other packet data like MPLS, ARP and a subset
of SMB (at time of writing).

"""
from setuptools import setup, Extension
from gitpy_versioning import get_version

try:
    from setuptools import find_packages
except ImportError:
    raise ImportError(
        'The setuptools package is required to install this library. See '
        '"https://pypi.python.org/pypi/setuptools#installation-instructions" '
        'for further instructions.'
    )

install_requires = (
    'steelscript>=2.0',
    'tzlocal',
)


# Build scripts automatically
scripts = {'console_scripts': [
    'netflow-player = steelscript.packets.commands.netflow_player:main'
]}

setup_args = {
    'name':                'steelscript.packets',
    'namespace_packages':  ['steelscript'],
    'version':             get_version(),

    # Update the following as needed
    'author':              'Riverbed Technology',
    'author_email':        'eng-github@riverbed.com',
    'url':                 'http://pythonhosted.org/steelscript',
    'license':             'MIT',
    'description':         'Base PCAP and inet packet classes.',
    'long_description':    __doc__,

    'packages': find_packages(exclude=('gitpy_versioning',)),
    'zip_safe': False,
    'install_requires': install_requires,
    'extras_require': None,
    'test_suite': '',
    'include_package_data': True,
    'platforms': 'Linux, Mac OS, Windows',
    'classifiers': [
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: System :: Networking',
    ],
    'setup_requires': [
        'cython',
        'setuptools>=18.0'
    ],
    'ext_modules': [
        Extension("steelscript.packets.core.pcap",
                  sources=["steelscript/packets/core/pcap.pyx"],
                  libraries=["pcap"],
                  cython_directives={"embedsignature": True,
                                     "binding": True}),
        Extension("steelscript.packets.core.inetpkt",
                  sources=["steelscript/packets/core/inetpkt.pyx"],
                  cython_directives={"embedsignature": True,
                                     "binding": True}),
        Extension("steelscript.packets.query.pcap_query",
                  sources=["steelscript/packets/query/pcap_query.pyx"],
                  cython_directives={"embedsignature": True,
                                     "binding": True}),
        Extension("steelscript.packets.protos.dns",
                  sources=["steelscript/packets/protos/dns.pyx"],
                  cython_directives={"embedsignature": True,
                                     "binding": True}),
    ],
    'entry_points': scripts
}

setup(**setup_args)
