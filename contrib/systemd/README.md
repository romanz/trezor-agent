# systemd user units for `trezor-agent`

Example units that run `trezor-agent` as a resident, socket-activated SSH agent
for your user. systemd holds the listening socket and starts the agent on the
first connection, so `SSH_AUTH_SOCK` is valid as soon as you log in and no agent
process needs to run while the socket is idle.

## Install

```
mkdir -p ~/.config/systemd/user
cp trezor-ssh-agent.socket trezor-ssh-agent.service ~/.config/systemd/user/
```

Edit `~/.config/systemd/user/trezor-ssh-agent.service` and replace `IDENTITY`
with your identity (e.g. `user@example.com`) or the path to a file listing your
exported public keys. Adjust the `trezor-agent` path in `ExecStart=` if it is
not installed in `/usr/bin`.

Then enable and start it:

```
systemctl --user enable --now trezor-ssh-agent.socket
```

Finally, point SSH at the socket by adding this to your `~/.bashrc` (or
equivalent):

```bash
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/trezor-agent/S.ssh"
```

See [`../../doc/README-SSH.md`](../../doc/README-SSH.md) for details and the
`--sock-path` option.
