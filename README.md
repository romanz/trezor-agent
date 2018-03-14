# onlykey-agent

SSH agent for the OnlyKey.

SSH is a popular remote access tool that is often used by administrators. Thanks to the OnlyKey SSH Agent remote access can be passwordless and more secure.

## SSH Agent Quickstart Guide

1) Install OnlyKey agent on your client machine:
```
$ sudo pip2 install onlykey
$ sudo pip2 install onlykey-agent
```

2) Generate public key using onlykey-agent
```
$ onlykey-agent user@example.com
```

3) Log in to your server as usual and copy the row containing the output from the previous step into ~/.ssh/authorized_keys file on your server

i.e.

`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFwsFGFI7px8toa38FVeBIKcYdBvWzYXAiVcbB2d1o3zEsRB6Lm/ZuCzQjaLwQdcpT1aF8tycqt4K6AGI1o+qFk= user@example.com`

4) From now on you can log in to your server using OnlyKey using the following command:
```
$ onlykey-agent -c user@example.com
```

5) This method can also be used for git push or other mechanisms that are using SSH as their communication protocol:
```
$ onlykey-agent user@example.com git push
```

## Installation

### MacOS Install with dependencies
Brew is required. To install visit https://brew.sh/
```
$ brew update && brew upgrade
$ brew install python
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```

### Ubuntu Install with dependencies
```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```

### Debian Install with dependencies
```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```

### Fedora/RedHat/CentOS Install with dependencies
```
$ yum update
$ yum install python-pip python-devel libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```
### OpenSUSE Install with dependencies
```
$ zypper install python-pip python-devel libusb-1_0-devel libudev-devel
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```

### Linux UDEV Rule

In order for non-root users in Linux to be able to communicate with OnlyKey a udev rule must be created as described [here](https://www.pjrc.com/teensy/td_download.html).

## Advanced Options

### Supported curves

Keys are generated unique for each user / host combination. By default OnlyKey agent uses NIST P256 but also supports ED25519 keys. ED25519 can be used as follows:

1) Generate ED25519 public key using onlykey-agent
```
$ onlykey-agent user@example.com -e ed25519
```

2) Log in using ED25519 public key
```
$ onlykey-agent -c user@example.com -e ed25519
```

You can also just type `-e e` instead of typing out the full `-e ed25519`

The project started from a fork [trezor-agent](https://github.com/romanz/trezor-agent) (thanks!). 
