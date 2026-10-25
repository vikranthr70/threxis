# Ubuntu VM live monitoring demonstration

**Status:** Experimental, manual-refresh read-only ingestion of real SSH authentication failures. Not a production SIEM or continuous agent. No real network attacks are initiated by THREXIS.

## Safe lab setup

Use a disposable Ubuntu VM that you own. Keep it on host-only networking, or otherwise restrict SSH to your host. Do not expose port 22 to the internet. Snapshot the VM first.

On the Ubuntu VM, install and enable the OpenSSH server only if needed:

```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

Check `sudo systemctl status ssh`. For the classroom demonstration, create **three manually entered failed SSH password attempts** to a nonexistent username from your host or from the Ubuntu VM itself. Do not use password guessing tools, brute-force loops, or any account you do not own.

A local Ubuntu-only example is:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no nonexistent_threxis_demo@127.0.0.1
```

Enter an arbitrary wrong password when prompted and terminate that connection after a failed attempt. Repeat manually until at least three failed-password log records exist within five minutes. Ubuntu's sshd configuration may disable password authentication, so check that the expected `Failed password for invalid user` lines actually appear before continuing.

Export **only the sshd failure log lines** from the Ubuntu VM. Depending on Ubuntu logging configuration:

```bash
sudo journalctl -u ssh --no-pager -o short-iso | grep 'Failed password'
```

Or:

```bash
sudo grep 'Failed password' /var/log/auth.log
```

Copy the resulting text to `data/live/ubuntu-auth.log` on the computer running Streamlit. Create the `data/live` directory if necessary. Do not commit or publish raw logs. Use a host-only shared folder or another authorized transfer method. This is an operator-controlled file handoff, not an automatic remote collection agent.

Start Streamlit and open **Live Ubuntu Monitor**, then press **Refresh log snapshot**. The dashboard parses SSH failed-password events, groups repeated failures by source IP, and runs the existing THREXIS detection engine. A rule triggers when at least three failures from the same source IP occur within five minutes. If no alert appears, inspect the exported lines, source IPs, and timestamps.

**Limitations:** The live view is a manual-refresh snapshot, not continuous streaming. It currently ingests SSH failure lines only. Real VM events are not yet passed into the readiness, evidence vault, or investigation pipeline. Those features remain in the separately labelled synthetic demonstration. Never present the two data sources as one case.

For a later production-grade monitoring extension, implement authenticated log transport, structured journald timestamps with timezone, persistent event offsets, rotation handling, source identity, provenance, access control, retention, and safe live-to-investigation adapters.
