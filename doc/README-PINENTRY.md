# Custom PIN entry

By default a standard GPG PIN entry program is used when entering your Trezor PIN, but it's difficult to use if you don't have a numeric keypad or want to use your mouse.

You can specify a custom PIN entry program (and separately, a passphrase entry program) such as [trezor-gpg-pinentry-tk](https://github.com/rendaw/trezor-gpg-pinentry-tk) to match your workflow.

##### 1. Install the PIN entry

Run

```
pip install trezor-gpg-pinentry-tk
```

##### 2. SSH

Add the flag `--pinentry trezor-gpg-pinentry-tk` to all calls to `trezor-agent`.

To automatically use this flag, add the line `pinentry=trezor-gpg-pinentry-tk` to `~/.ssh/agent.config`.  **Note** this is currently broken due to [this dependency issue](https://github.com/bw2/ConfigArgParse/issues/114).

If you specify the flag in a systemd `.service` file you may need to use the absolute path to `trezor-gpg-pinentry-tk`.  You may also need to add this line:

```
Environment="DISPLAY=:0"
```

to the `[Service]` section to tell the PIN entry program how to connect to the X11 server.

##### 3. GPG

If you haven't completed initialization yet, run:

```
$ (trezor|keepkey|ledger)-gpg init --pinentry trezor-gpg-pinentry-tk "Roman Zeyde <roman.zeyde@gmail.com>"
```

to configure the PIN entry at the same time.

Otherwise, open `$GNUPGHOME/trezor/gpg-agent.conf` and add this line:

```
pinentry-program trezor-gpg-pinentry-tk
```

Kill the agent (processes `run-agent.sh` and `trezor-gpg-agent`).

##### 4. Troubleshooting

Add:

```
log-file /home/yourname/.gnupg/trezor/gpg-agent.log
verbosity 2
```

to `$GNUPGHOME/trezor/gpg-agent.conf` and restart the agent.

Any problems running the PIN entry program should appear in the log file.
