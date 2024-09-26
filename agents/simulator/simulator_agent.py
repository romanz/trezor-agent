from libagent import age, signify, gpg, ssh
from libagent.device.simulator import Simulator as DeviceType

age_tool = lambda: age.main(DeviceType)
ssh_agent = lambda: ssh.main(DeviceType)
gpg_tool = lambda: gpg.main(DeviceType)
gpg_agent = lambda: gpg.run_agent(DeviceType)
signify_tool = lambda: signify.main(DeviceType)
