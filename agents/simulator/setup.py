#!/usr/bin/env python
from setuptools import setup

setup(
    name='simulator_agent',
    version='0.0.1',
    description='Using a simulation of a hardware device as SSH/GPG/age agent',
    author='Roman Zeyde',
    author_email='dev@romanzey.de',
    url='http://github.com/romanz/trezor-agent',
    scripts=['simulator_agent.py'],
    install_requires=[
        'libagent>=0.14.0'
    ],
    platforms=['POSIX', 'win32'],
    classifiers=[
        'Environment :: Console',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'Topic :: Communications',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    entry_points={'console_scripts': [
        'simulator-agent = simulator_agent:ssh_agent',
        'simulator-gpg = simulator_agent:gpg_tool',
        'simulator-gpg-agent = simulator_agent:gpg_agent',
        'simulator-signify = simulator_agent:signify_tool',
        'age-plugin-simulator = simulator_agent:age_tool',
    ]},
)
