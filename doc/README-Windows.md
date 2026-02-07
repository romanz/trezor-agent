# Windows installation and usage instructions

## Preface

Since this library supports multiple hardware security devices, this document uses the term `<device>` in commands to refer to the device of your choice.

Installation and building has to be done with administrative privileges. Without these, the agent would only be installed for the current user, and could therefore not be used as a service. To run an administrative shell, hold the Windows key on the keyboard, and press R. In the input box that appears, type either "cmd" or "powershell" (Based on your preference. Both work), and then hold the Ctrl and Shift keys, and press Enter. A User Account Control dialog will pop up. Simply press "Yes".

These instructions makes use of [WinGet Client](https://github.com/microsoft/winget-cli) which is bundled with Windows 10+. If using an older version of Windows, it is possible to use [Chocolatey](https://community.chocolatey.org/courses/installation/installing?method=installing-chocolatey) instead. Direct links to installer downloads are also provided, if manual install is preferred.

## Installation

### 1. Install Python

Install using WinGet, or [download the installer directly](https://www.python.org/downloads/windows/)
```
winget install python3
```

Verify Python is installed and in the path:
```
python --version
```
Example output:
```
C:\WINDOWS\system32>python --version
Python 3.11.4
```
You may need to close and reopen the shell to update environment variables. Alternately, if you have Chocolatey installed, you may use `refreshenv` instead.

Ensure `pip` is available and up to date:
```
python -m pip install --upgrade pip
```

### 2. Install the agent

Run the following command:
```
pip install <device>-agent
```

**Note:** Some agent packages use underscore instead of hyphen in the package name. For example, the Trezor agent package is `trezor-agent`, while the Ledger agent package is `ledger_agent`. This only applies to the `pip` package names. All other commands use a hyphen for all devices.

## Building from source

First, ensure you have Python installed, as described in the above section. Next, ensure you have Git installed:
```
winget install -e --id Git.Git
```

Create a directory for the source code, and clone the repository. Before running this command, you may want to change to a directory where you usually hold documents or source code packages.
```
git clone https://github.com/romanz/trezor-agent.git
```

Build and install the library:
```
pip install -e trezor-agent
```

Build and install the agent of your choice:
```
pip install -e trezor-agent/agents/<device>
```

## Usage

### Using SSH

You can use SSH either as a service offering keys in the background to any SSH clients, or to run an SSH client directly. For the latter case, you will need to install OpenSSH.

#### Installing OpenSSH

If using Windows 10+, first open the optional features dialog:
```
fodhelper
```
Click on the "Add a feature" button. In the "Find an available optional feature", type "OpenSSH Client". If you can't find it, it may already be installed. You can, instead, look for it "Find an installed optional feature". If it is not installed, simply click the checkbox next to it, and then click on "Install".

Alternatively, you can install the latest version using WinGet:
```
winget install "openssh beta"
```

If using an older version of Windows, you can install it using Chocolatey instead:
```
choco install openssh
```

#### Set up a key

You will need to do this once for every server you to which intend to connect using your device. Create and save the key using the following command:
```
<device>-agent -e ed25519 user@myserver.com >> %USERPROFILE%/.ssh/<device>.pub
```
Where `user` is the user with which you intend to connect (e.g. `root`), and `myserver.com` is the server to which you intend to connect (e.g. `github.com`). **Note:** The device will have to be unlocked during this operation. But no confirmation is required.

You will now need to copy the contents of the created file to the server's `~/.ssh/authorized_keys`. The method from doing this can vary from server to server. If you have direct access (e.g. via a password), you may edit the file directly. Public servers, like GitHub for example, may allow uploading or pasting the key via a `Settings` section, such as `Access` or `SSH keys`. Refer to the specific service's help pages to see instructions regarding adding SSH keys to the server.

If you do not intend to run the agent as a service, you may delete the `%USERPROFILE%/.ssh/<device>.pub` file after uploading the key.

#### Connect to an SSH server directly

Once set up, use the following command to connect to the server:
```
<device>-agent -e ed25519 user@myserver.com -c
```

You will be required to authorize the use of the key on the device.

#### Running as a service

Adding services to Windows requires the use of a third-party tool. The recommended tool for this task is [NSSM](https://nssm.cc/download). It can be installed using the direct link, or via Chocolatey:
```
choco install nssm
```

To set up the service, use the following commands:
```
nssm install "<device>-agent" <device>-agent "file:%USERPROFILE%/.ssh/<device>.pub" -f --sock-path=\\.\pipe\openssh-ssh-agent
nssm set "<device>-agent" DisplayName "Hardware Device SSH Authentication Agent"
```

Before running the service, make sure OpenSSH's `ssh-agent` is not running:
```
nssm stop ssh-agent
nssm set ssh-agent Start SERVICE_DISABLED
```
If you receive the error `The specified service does not exist as an installed service.`, this just means OpenSSH is not installed, and you may proceed to the next step.

Then start the service using:
```
nssm set "<device>-agent" Start SERVICE_AUTO_START
nssm start "<device>-agent"
```

If you do not need it anymore, you can delete the service at any time using the command:
```
nssm remove "<device>-agent" confirm
```

#### Using the agent with PuTTY

The SSH authentication agent is designed to work with OpenSSH and compatible programs. Using it with PuTTY requires a third-party tool. The recommended tool for this task is [WinSSH-Pageant](https://github.com/ndbeals/winssh-pageant/releases).

You may download the installer directly, or install it using WinGet:
```
winget install winssh-pageant
```

Once installed, it will automatically run on startup, and deliver key requests to any running SSH agent. This requires the agent to be running as a service. See the section above.

### Using GPG

To use GPG on Windows, you will need [Gpg4win](https://www.gpg4win.org/).

You can [download it directly](https://www.gpg4win.org/thanks-for-download.html) or install it via WinGet
```
winget install -e --id GnuPG.Gpg4win
```
Or using Chocolatey:
```
choco install gpg4win
```

You must first create a signing identity:
```
<device>-gpg init -e ed25519 "My Full Name <myemail@mymailhost.com>"
```
You will be asked for confirmation on your device **twice**.

This will create a new profile in `%USERPROFILE%/.gnupg/<device>`. You may now use GPG while specifying a home folder. For example:
```
echo 123 | gpg --clearsign --homedir "%USERPROFILE%/.gnupg/<device>" | gpg --verify --homedir "%USERPROFILE%/.gnupg/<device>"
```
The above example command will require a single confirmation on your device.

If you wish to use GPG via other programs (e.g. Kleopatra), you will need to set the created folder as your default profile:
```
setx /m GNUPGHOME "%USERPROFILE%/.gnupg/<device>"
```

If you wish to use a different identity, you will need to delete the folder `%USERPROFILE%/.gnupg/<device>`, and create a new identity as described above.

### Using AGE

[AGE File Encryption](https://age-encryption.org/) is a tool for encrypting and decrypting files. You will require a Windows version of the tool in order to use it. The recommended tool is [WinAge](https://github.com/spieglt/winage/releases). A WinGet package is not available for this tool.

Before proceeding, you will need to create an identity:
```
age-plugin-<device> -i MyIdentityPath > age.identity
```
Where `MyIdentityPath` is any name of your choice for this encryption identity. This text will appear on your device every time you encrypt or decrypt with this identity.

The content of the file may look something like this:
```
# recipient: agewnc7uu1btfhmr95dia9txto4ke1lm7azka3x1zkh17fk52guykrc2xk11
# SLIP-0017: MyIdentityPath
AGE-PLUGIN-TREZOR-1F4U5JER9DE6XJARE2PSHG6Q4UFNE8
```

Next, in Explorer, right click on the file you want to encrypt, and select `Encrypt with age`. Pick the `Recipient` mode. Copy the code appearing after `recipient:` in your `age.identity` file, e.g. `agewnc7uu1btfhmr95dia9txto4ke1lm7azka3x1zkh17fk52guykrc2xk11`, and paste it in the `Recipient, recipient file, or identity file` box. Finally, click on `Encrypt`, and pick the file location to save the encrypted file. Be sure to give it an `.age` suffix, so it can be easily decrypted.

To decrypt a file, simply open (double click in Explorer) the `.age` file. A decryption dialog will pop up. In the `Select identity file` box, select your `age.identity` file. Click on `Decrypt`, and pick the file location to save the encrypted file.

**Note:** At the moment, encrypting using the identity file is not supported. You must use the recipient id instead.

### Using Signify

[Signify](https://man.openbsd.org/OpenBSD-current/man1/signify.1) is a tool for signing messages and files, so that third parties may verify the validity of those files.

To sign a file, use the following command:
```
type myfile.txt | <device>-signify sign MyIdentityPath -c "My comment" > myfile.sig
```
You will be asked for confirmation on your device **twice**.

To verify the signature, you will first need to export your public key associated with the identity:
```
<device>-signify pubkey MyIdentityPath > myfile.pub
```
You will not be asked for confirmation, but your device must be unlocked.

You will need a tool to verify the signature. The recommended tool is [Minisign](https://github.com/jedisct1/minisign/releases).

You may download it directly, or using Chocolatey:
```
choco install minisign
```
Or [Scoop](https://github.com/ScoopInstaller/Scoop):
```
scoop install minisign
```
A WinGet package is not available.

Verify the validity of the signature using the following command:
```
minisign -V -x myfile.sig -p myfile.pub -m myfile.txt
```
This can be done without access to the device, allowing third parties to verify the validity of your files. Only the public key file `myfile.pub`, needs to be securely transferred for the signature to be secure.

An example output would be:
```
C:\Users\MyUser>minisign -V -x myfile.sig -p myfile.pub -m myfile.txt
Signature and comment signature verified
Trusted comment: My comment
```
An invalid output (If the file was corrupted or tampered with) would look like:
```
C:\Users\MyUser>minisign -V -x myfile.sig -p myfile.pub -m myfile.txt
Signature verification failed
```

## Troubleshooting

If you receive the following error while building:
```
error: [WinError 32] The process cannot access the file because it is being used by another process: 'c:\\python311\\lib\\site-packages\\libagent-0.14.8-py3.11.egg'
```
Manually delete the specified file, and try again.

If you receive the following error while building:
```
Error: Couldn't find a setup script in C:\Users\MyUser\AppData\Local\Temp\easy_install-2mn9q14a\semver-3.0.1.tar.gz
```
Your Python version may be out of date. Follow the Python installation instructions above. Restart your administrative shell if the update is not being detected.

If while running you receive the following error:
```
ModuleNotFoundError: No module named 'pywintypes'
```
Use the following commands using administrative shell:
```
pip uninstall -y pywin32
pip install pywin32
```

If while running you receive the following error:
```
Failed to enumerate WebUsbTransport. FileNotFoundError: Could not find module 'libusb-1.0.dll' (or one of its dependencies). Try using the full path with constructor syntax.
```
Use the following commands using administrative shell:
```
pip uninstall -y libusb1
pip install libusb1
```

If while running as a service you receive the following error:
```
pywintypes.error: (5, 'CreateNamedPipe', 'Access is denied.')
```
Ensure the OpenSSH Authentication Agent is not running:
```
nssm stop ssh-agent
```
Also look for any other SSH agents you may have installed on your system.

### Signing Git commits with GPG

If you receive the error:
```
gpg: invalid size of lockfile 'C:\Users\MyUser/gnupg/trezor/pubring.kbx.lock'
```
It means Git is trying to run the wrong version of GPG. First, Figure out where your GPG is:
```
where gpg
```
Example output:
```
C:\Users\MyUser>where gpg
C:\Program Files (x86)\GnuPG\bin\gpg.exe
```
Now set this value in your Git global config:
```
git config --global gpg.program "C:\Program Files (x86)\GnuPG\bin\gpg.exe"
```

If you receive the error:
```
signing failed: No secret key
```
It means Git isn't selecting the correct key for signing. Normally, Git will look for a key with the same identity name as your committer name and email. However, you can explicitly select the secret key you want to use. First, you need to know your key id. There are three methods to do so. You can do this via command line:
```
gpg --list-secret-keys --keyid-format=long
```
Example output:
```
C:\Users\MyUser>gpg --list-secret-keys --keyid-format=long
C:\Users\MyUser\.gnupg\trezor\pubring.kbx
----------------------------------------
sec   ed25519/100A53DB673C6714 1970-01-01 [SC]
      1E98503AC72ECBF78CDC3E415188B41C865FD25C
uid                 [ultimate] My Full Name <myemail@mymailhost.com>
ssb   cv25519/BD4CAB3E278E645F 1970-01-01 [E]
```
The key id is the value in the `sec` line, coming after the `/`. So, in the above example, it is `100A53DB673C6714`.

You can also obtain the keyid from `gpg.conf` as so:
```
type "%USERPROFILE%\.gnupg\<device>\gpg.conf"
```
Example output:
```
C:\Users\MyUser>type "%USERPROFILE%\.gnupg\<device>\gpg.conf"
# Hardware-based GPG configuration
agent-program "C:\Users\MyUser/.gnupg/trezor\run-agent.bat"
personal-digest-preferences SHA512
default-key 0x100A53DB673C6714
```
The key id appears after `default-key 0x`.

The last method is to run Kleopatra, which comes bundled with Gpg4win. Upon opening it, it will show a list of identities associated with your default profile. The key id will simply appear in the rightmost column titled `Key-ID`. However, it will appear with extra spaces, e.g. `100A 53DB 673C 6714`. You can copy it simply by clicking on the text, holding Ctrl, and pressing C.

Once you have the key id, use the following command to set the default key for Git:
```
git config --global user.signingkey 100A53DB673C6714
```
Alternately, you can pick a specific secret key for a commit using the `-S` command line argument.
```
git commit -S100A53DB673C6714 -m "My commit message"
```

You may also force signing on all commits by default:
```
git config --global commit.gpgsign true
```
If you prefer to only sign specific commits, you can turn it off:
```
git config --global --unset commit.gpgsign
```
