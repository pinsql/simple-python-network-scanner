# simple-python-network-scanner

![ci](https://github.com/pinsql/simple-python-network-scanner/actions/workflows/ci.yml/badge.svg)

ARP-sweep your LAN and see who's home. one file, one dependency, zero chill.

## install

```bash
pip install -r requirements.txt
```

## use

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24
```

or `sudo ./network_scanner.py -t 192.168.1.0/24`, it's executable.

needs root because ARP goes out on raw sockets. forget `sudo` and it tells you instead of dumping a traceback.

| flag | what it does |
|---|---|
| `-t`, `--target` | IPv4 address or CIDR range to sweep (required) |
| `-i`, `--iface` | interface to send from (default: whatever scapy picks) |
| `--timeout` | seconds to wait for replies (default: 2) |
| `--json` | JSON output, pipe it into `jq` |

```text
📡 Devices on the network (aka your neighbors?):

IP Address              MAC Address
-----------------------------------------
192.168.1.1             aa:bb:cc:dd:ee:ff
192.168.1.42            11:22:33:44:55:66
```

```bash
sudo python3 network_scanner.py -t 10.0.0.0/24 --json | jq -r '.[].ip'
```

## tests

```bash
pip install pytest && pytest -q
```

no root or real network needed, the packet layer is mocked.

## legal

only scan networks you own or have written permission to test. no scope, no scan.
