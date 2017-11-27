*Requires OpenSSL 1.1.0*

## To install OpenSSL 1.1.0 on Mac:

	$ brew update && brew upgrade
	$ brew install openssl@1.1
	$ /usr/local/opt/openssl@1.1/bin/openssl

**Note that you have to put the full path to OpenSSL so for example to run a command it would look like this:  /usr/local/opt/openssl@1.1/bin/openssl genpkey -algorithm X25519 -out X25519.key**

##To install OpenSSL 1.1.0 on Debian Linux:

	$ apt update && apt install openssl

## To install OpenSSL 1.1.0 on Ubuntu Linux:

  Follow instructions here - https://forums.servethehome.com/index.php?resources/installing-openssl-1-1-0-on-ubuntu.21/

## To install OpenSSL 1.1.0 on Windows:

  The OpenSSL project does not distribute Windows Binaries but they do provide a list of 3rd parties that provide binaries on their wiki.
  - Download and install binary - https://slproweb.com/download/Win32OpenSSL-1_1_0g.exe
  - To run OpenSSL - C:\OpenSSL-Win32\bin\openssl.exe

Note that you have to put the full path to OpenSSL so for example to run a command it would look like this: C:\OpenSSL-Win32\bin\openssl.exe genpkey -algorithm X25519 -out X25519.key
