# Cowrie configuration

Cowrie itself is upstream code and is installed outside this repo (`~/cowrie`). Only our configuration choices are recorded here.

Local development settings in `etc/cowrie.cfg`:

| Setting | Value | Why |
|---|---|---|
| `hostname` | `webserver01` | The default hostname is a well-known honeypot giveaway |
| `listen_endpoints` | `tcp:2222:interface=0.0.0.0` | Port 22 is taken by the real SSH daemon on the dev VM |

Add further changes (fake filesystem, login policy, output plugins) to this table as they are made, with the reason for each.
