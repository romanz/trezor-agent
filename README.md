# onlykey-agent

SSH agent for the OnlyKey.

The project started from a fork [trezor-agent](https://github.com/romanz/trezor-agent) (thanks!).

**Still in early development.**

## Installation

You will probably need to run these commands as root (e.g. with `sudo`), unless you have changed your system configuration to support the installation of packages as a normal user.



### Ubuntu
```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip2 install -U setuptools pip
$ pip2 install Cython
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```
### Debian
```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip2 install -U setuptools pip
$ pip2 install Cython
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```
### Fedora/RedHat
```
$ yum update
$ yum install python-pip python-devel libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip2 install -U setuptools pip
$ pip2 install Cython
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```
### OpenSUSE
```
$ zypper install python-pip python-devel libusb-1_0-devel libudev-devel
$ pip2 install Cython
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```

## Getting started

In order for non-root users in Linux to be able to communicate with OnlyKey a udev rule must be created as described [here](https://www.pjrc.com/teensy/td_download.html).

### Create Private Key

Currently the Onlykey SSH Agent supports ED25519 or NIST P-256 keys.

#### Create Private Key on OnlyKey (Recommended)

A new key may be generated on OnlyKey as follows:

To create a new ED25519 SSH key (Default):

$ onlykey-agent test@hostname.com --slot 1 -v -g
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDMcB8Fu1LYxIrFwbRNoc7J7mkVF4VDrJKZO/1dG2Iwb test@hostname.com

To create a new NIST P-256 SSH key:

$ onlykey-agent test@hostname.com --slot 1 -v -g -e nist256p1
ecdsa-sha2-nistp256 AAAAC3NzaC1lZDI1NTE5AAAAIDMcB8Fu1LYxIrFwbRNoc7J7mkVF4VDrJKZO/1dG2Iwb test@hostname.com

Append the output from this command i.e.

`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDMcB8Fu1LYxIrFwbRNoc7J7mkVF4VDrJKZO/1dG2Iwb test@hostname.com`

to `~/.ssh/authorized_keys` configuration file at `hostname.com`, so the remote server would allow you to login using the corresponding private key signature.

#### Create Private Key using OpenSSL

First make sure you have OpenSSL version 1.1.0 or later. Check the version by running 'openssl version'

Here is a guide to installing OpenSSL version 1.1.0 or later if you do not have it
[OpenSSL Install Help](https://github.com/trustcrypto/onlykey-agent/blob/master/OPENSSL.md)

A new key may be generated offline as follows:

$ openssl list -public-key-algorithms | grep X25519

You should see something like this:
Name: OpenSSL X25519 algorithm
	OID: X25519
	PEM string: X25519

If not you will need an up-to-date version of OpenSSL to continue.

	$ openssl genpkey -algorithm X25519 -out X25519.key -aes256
	Enter PEM pass phrase:
	Verifying - Enter PEM pass phrase:
	$ openssl pkey -in X25519.key -noout -text 2>/dev/null |   sed -n '/priv:/,/pub:/p' | grep -o '[0-9a-f]\{2\}' | tr -d ' \n'
	Enter pass phrase for X25519.key:
	d86a400b75130eea2e204635dcf84c4a6f8e57e2be899da4d1e469b614ca786a

Copy the output from this command i.e.

`d86a400b75130eea2e204635dcf84c4a6f8e57e2be899da4d1e469b614ca786a`

Open the OnlyKey app and select the Keys tab.
Follow the onscreen instructions to put OnlyKey into config mode.

Once OnlyKey is in config mode (Flashing Red):
- Select Type
- Select desired Slot
- Paste the key you copied in into the Key field
- Select “Set as signature key” and “Set as authentication key”

Save to OnlyKey, and you should see a message confirming success.

Once this is complete be sure to delete the key you created (X25519.key) or store it somewhere safe as a backup

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
