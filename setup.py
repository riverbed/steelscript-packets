# Copyright (c) 2017 Riverbed Technology, Inc.
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
from setuptools import setup, Extension, Command
# from distutils.core import setup
# from distutils.extension import Extension
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
    USE_CYTHON = True
    ext = '.pyx'
except ImportError:
    USE_CYTHON = False
    ext = '.c'

install_requires = (
    'steelscript',
    'Cython',
)

extensions = [
    Extension("steelscript.packets.core.pcap",
              ["steelscript/packets/core/pcap{0}".format(ext)]),
    Extension("steelscript.packets.core.inetpkt",
              ["steelscript/packets/core/inetpkt{0}".format(ext)]),
    Extension("steelscript.packets.query.pcap_query",
              ["steelscript/packets/query/pcap_query{0}".format(ext)]),
]

if USE_CYTHON:
    extensions = cythonize(extensions)

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
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking',
    ],
    'ext_modules': extensions,
}

setup(**setup_args)
