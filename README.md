# onlykey-agent

SSH agent for the OnlyKey.

The project started from a fork [trezor-agent](https://github.com/romanz/trezor-agent) (thanks!).

**Still in early development.**

## SSH Agent Quickstart Guide

1) Install OnlyKey agent on your client machine:

$ sudo pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ sudo pip2 install git+git://github.com/trustcrypto/onlykey-agent.git

2) Generate public key using onlykey-agent:

$ onlykey-agent user@example.com

3) Log in to your server as usual and copy the row containing the output from the previous step into ~/.ssh/authorized_keys file on your server

i.e.

`ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFwsFGFI7px8toa38FVeBIKcYdBvWzYXAiVcbB2d1o3zEsRB6Lm/ZuCzQjaLwQdcpT1aF8tycqt4K6AGI1o+qFk= user@example.com`

4) From now on you can log in to your server using OnlyKey using the following command:

$ onlykey-agent -c user@example.com


5) This method can also be used for git push or other mechanisms that are using SSH as their communication protocol:

$ onlykey-agent user@example.com git push


## SSH Agent Advanced Topics

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
$ pip2 install -U setuptools pip
$ pip2 install Cython
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```

### Debian Install with dependencies
```
$ apt update && apt upgrade
$ apt install python-pip python-dev libusb-1.0-0-dev libudev-dev
$ pip2 install -U setuptools pip
$ pip2 install Cython
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```

### Fedora/RedHat/CentOS Install with dependencies
```
$ yum update
$ yum install python-pip python-devel libusb-devel libudev-devel \
              gcc redhat-rpm-config
$ pip2 install -U setuptools pip
$ pip2 install Cython
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```
### OpenSUSE Install with dependencies
```
$ zypper install python-pip python-devel libusb-1_0-devel libudev-devel
$ pip2 install Cython
$ pip2 install git+git://github.com/trustcrypto/python-onlykey.git
$ pip2 install git+git://github.com/trustcrypto/onlykey-agent.git
```

### Linux UDEV Rule

In order for non-root users in Linux to be able to communicate with OnlyKey a udev rule must be created as described [here](https://www.pjrc.com/teensy/td_download.html).

### Create New Private Key

Currently the Onlykey SSH Agent supports ED25519 or NIST P-256 keys. A default key is created automatically in slot # 32. You can use different private keys for different servers, OnlyKey supports up to 32 ECC keys.

WARNING - Generating keys overwrites any existing keys.

#### Create New Private Key on OnlyKey

A new key may be generated on OnlyKey as follows:

First make sure your OnlyKey is in config mode by holding the 6 button down for 5 or more seconds and then re-entering your PIN.

To create a new NIST P-256 key in slot 1:

`$ onlykey-agent test@hostname.com --slot 1 -g`

To create a new ED25519 key in slot 1:

`$ onlykey-agent test@hostname.com --slot 1 -g ssh-ed25519`

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
