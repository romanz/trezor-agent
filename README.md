# onlykey-agent

SSH agent for the OnlyKey.

The project started from a fork [trezor-agent](https://github.com/romanz/trezor-agent) (thanks!).

**Still in early development.**

## Installation

### Debian 
```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip install -U setuptools pip
$ pip install Cython
$ pip install git+git://github.com/trustcrypto/python-onlykey.git
$ pip install git+git://github.com/trustcrypto/onlykey-agent.git
```
### Fedora/RedHat
```
$ yum update
$ yum install python-pip python-devel libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip install -U setuptools pip
$ pip install Cython
$ pip install git+git://github.com/trustcrypto/python-onlykey.git
$ pip install git+git://github.com/trustcrypto/onlykey-agent.git
```

## Getting started

In order for non-root users in Linux to be able to communicate with OnlyKey a udev rule must be created as described [here](https://www.pjrc.com/teensy/td_download.html).

### Public key generation

**Run Verbose**

	$ onlykey-agent test@hostname.com --slot 1 -v
	2017-09-19 00:19:46,175 INFO         getting public key (ed25519) from OnlyKey...                                   
	ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDMcB8Fu1LYxIrFwbRNoc7J7mkVF4VDrJKZO/1dG2Iwb test@hostname.com
	2017-09-19 00:19:47,180 INFO         disconnected from OnlyKey   
	
**Run**

	$ onlykey-agent test@hostname.com --slot 1
	ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDMcB8Fu1LYxIrFwbRNoc7J7mkVF4VDrJKZO/1dG2Iwb test@hostname.com
		
Append the output from this command i.e. 

`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDMcB8Fu1LYxIrFwbRNoc7J7mkVF4VDrJKZO/1dG2Iwb test@hostname.com`

to `~/.ssh/authorized_keys` configuration file at `hostname.com`, so the remote server would allow you to login using the corresponding private key signature.

### Usage

**Run:**

	$ onlykey-agent test@hostname.com --slot 1 -v -c
	2017-09-19 00:15:29,861 INFO         getting public key (ed25519) from OnlyKey...                                   
	2017-09-19 00:15:30,867 INFO         using SSH public key: e8:00:d9:9a:6d:af:81:fd:4a:46:51:c9:80:75:c8:4a           
	2017-09-19 00:15:30,942 INFO         please confirm user "test" login to "test@hostname.com" using OnlyKey         
	2017-09-19 00:15:30,946 INFO         Please enter the 3 digit challenge code on OnlyKey (and press ENTER if necessary)                    
	2 1 4
	
*Enter the shown challenge code on OnlyKey, 2-1-4*
