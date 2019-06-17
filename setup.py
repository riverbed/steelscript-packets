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

try:
    from Cython.Build import cythonize
except ImportError:
    raise ImportError("Steelscript-Packets requires Cython.")

install_requires = (
    'steelscript>=2.0',
    'tzlocal',
    'Cython',
)

extensions = [
    Extension("steelscript.packets.core.pcap",
              ["steelscript/packets/core/pcap.pyx"],
              libraries=["pcap"]),
    Extension("steelscript.packets.core.inetpkt",
              ["steelscript/packets/core/inetpkt.pyx"]),
    Extension("steelscript.packets.query.pcap_query",
              ["steelscript/packets/query/pcap_query.pyx"]),
    Extension("steelscript.packets.protos.dns",
              ["steelscript/packets/protos/dns.pyx"]),
]
for e in extensions:
    e.cython_directives = {"embedsignature": True,
                           "binding": True}
extensions = cythonize(extensions)

# Build scripts automatically
scripts={'console_scripts': [
    'netflow-player = steelscript.packets.commands.netflow_player:main']
}

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
    'ext_modules': extensions,
    'entry_points': scripts
}

setup(**setup_args)
