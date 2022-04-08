#!/usr/bin/env python
from distutils.core import setup
from nftables import NFTABLES_VERSION

setup(name='nftables',
      version=NFTABLES_VERSION,
      description='Libnftables binding',
      author='Netfilter project',
      author_email='coreteam@netfilter.org',
      url='https://netfilter.org/projects/nftables/index.html',
      packages=['nftables'],
      provides=['nftables'],
      package_dir={'nftables':'.'},
      package_data={'nftables':['schema.json']},
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python',
          'Topic :: System :: Networking :: Firewalls',
          ],
      )
