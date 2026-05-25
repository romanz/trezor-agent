from libagent import age, signify, gpg, ssh
from libagent.device.onlykey import OnlyKey as DeviceType

age_tool = lambda: age.main(DeviceType)
ssh_agent = lambda: libagent.ssh.main(DeviceType)
gpg_tool = lambda: libagent.gpg.main(DeviceType)
gpg_agent = lambda: libagent.gpg.run_agent(DeviceType)
signify_tool = lambda: signify.main(DeviceType)
