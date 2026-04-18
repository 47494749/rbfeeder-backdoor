# FORENSIC ANALYSIS: MALWARE ON RASPBERRY PI (RBFEEDER / RADARBOX)

I was hacked and never noticed until yesterday (17.04.2026)!

It all started many years ago when I bought a Raspberry Pi 3 to share aircraft positions with FlightRadar24, ADSBexchange, RadarBox and a few others. I installed everything and left it running for years without ever checking on it. I'd only reboot it when I got a notification that it was offline.

A few days ago, wanting to "practice" a bit with AI, I thought I'd take a look at dump1090 (an open source project for ADS-B decoding). I had the AI check what was missing compared to the technical specifications... within 3 minutes I had already asked it to add what was still missing.

I had it compiled and tested on the Raspberry. Everything worked fine until I hit a port conflict. I asked the AI to investigate and it flagged a suspicious process: a certain **"dump1090-rb"** running from `/tmp` and connecting to an Alibaba Cloud server in China (`8.219.81.242`).

The AI initially identified it as the RadarBox client, the relay that reads ADS-B data from port 30005 and forwards it to the remote server. But the fact that it was running from `/tmp`, was UPX-packed and obfuscated didn't sit right with me. At that point I stopped all the sharing services running on the Raspberry, downloaded the binary that was running in /tmp/ and decompressed it for a closer look.

That's where the real analysis began.

---

> **IMPORTANT NOTE ON METHODOLOGY**
>
> The reverse engineering analysis was performed **EXCLUSIVELY** on the malicious files found on the device (the RAT `upevm`, the FRP client disguised as `dump1090-rb`, the dropper script `rbfeeder.sh` and the binaries downloaded from the C2 server).
>
> The **rbfeeder software by AirNav (RadarBox) was NOT reverse engineered**. The information about rbfeeder's behavior was gathered by the AI using standard Linux system tools automatically:
> - `readelf` to read the imported symbol table
> - `strings` to extract readable text strings
> - `strace` to observe system calls in real time
> - `ss`/`netstat` for active network connections
> - `ps`/`systemctl` for running processes and services
>
> No disassembly or reverse engineering was performed on AirNav's code. The extracted information (imported function names, log strings, network connections) can all be obtained with standard tools available on any Linux system.

---


## 1. INFECTION TIMELINE ON MY RASPBERRY

| Date | Event |
|------|-------|
| **2023-02-22** | rbfeeder v0.3.5 installed from the official repository `apt.rb24.com` |
| **2023-02-22** | The rbfeeder service starts and connects to the AirNav server (`212.224.72.114:33755`) |
| **2023-07-27** | First available log entry in `rbfeeder.log` (485MB, never rotated). The log contains ONLY periodic statistics. |
| **2025-08-18 10:03:47** | `upev.service` created on the system, **date of the first infection**. This is when the malware installation command was executed. |
| **2025-09-10 03:00:43** | RAT binary `upevm` compiled (version "20250910") |
| **2025-10-17 05:25:39** | Symlink `/usr/bin/upev` → `/usr/bin/upevm` recreated (automatic RAT update) |
| **2025-10-22 04:09:57** | Binary `upevm` updated to a new version |


## 2. FULL RECONSTRUCTION OF THE ATTACK CHAIN BASED ON EVENTS IN THE REMAINING LOGS

**Phase 1: SOFTWARE INSTALLATION** (February 2023)
- User installs rbfeeder from the official RadarBox repository
- A permanent connection to the AirNav server is established

**Phase 2: COMMAND INJECTION** (~August 18, 2025)
- A command is sent through the proprietary protocol
- rbfeeder receives it and executes it via system shell (more on this later)
- The command downloads and runs a malicious script from the domain `apt.transponderlive.org`

**Phase 3: MALWARE INSTALLATION** (August 18, 2025, ~10:03)
- The script runs with **ROOT** privileges (because rbfeeder runs as root, at least on my Raspberry)
- Resolves the C2 server domain bypassing local DNS
- Downloads the RAT binary with hardcoded credentials
- Installs:
  - `/usr/bin/upevm` (RAT binary written in Go, UPX-packed)
  - `/usr/bin/upev` → symlink to the binary
  - `upev.service` (systemd service disguised as "udev")
- Cleans traces from crontab

**Phase 4: RAT ACTIVE** (from August 2025)
- The malicious service starts on every boot
- Communicates with the C2 server via HTTPS with AES-256 encryption
- Receives the network tunnel configuration
- Starts a tunnel that exposes ADS-B data to the outside

**Phase 5: AUTOMATIC UPDATES** (October 2025)
- The RAT periodically updates itself by downloading new versions (server files updated in March and April 2026)
- Oct 17: symlink recreated
- Oct 22: binary updated


## 3. INFECTION CHAIN: HOW THE MALWARE ARRIVES

The official RadarBox installer (`apt.rb24.com`) and the Debian package turned out to be clean: they only install the rbfeeder binary, the configuration file and the systemd service. No malicious script in the package.

Analyzing rbfeeder with standard Linux tools (`readelf`, `strings`) revealed that the binary imports the `posix_spawn` function and contains strings like `"Run command: %s"`, `"/bin/sh"`, `"Expected CMD has arrived!"`, indicators of a capability to execute commands received from the server (BACKDOOR!)

**The infection happens AFTER installation**, through the proprietary communication protocol between rbfeeder and the AirNav server: the server sends a command, rbfeeder executes it as a system shell command.

The malicious script deletes its own traces after execution.

**Infection timestamps** (from filesystem):

| Event | Timestamp |
|-------|-----------|
| `upev.service` created | 2025-08-18 10:03:47 |
| Symlink recreated | 2025-10-17 05:25:39 |
| Binary updated | 2025-10-22 04:09:57 |

**The attack leaves no traces because:**

1. The command is executed via proprietary protocol and not saved in any logs
2. The dropper installs files directly, without using the package manager
3. The dropper cleans the crontab
4. System logs from the infection period (August-October 2025) were rotated and lost, only those from April 2026 remain
5. The rbfeeder log (485MB) contains only statistics, never the executed commands
6. No traces in `bash_history`, `auth.log` or `journal` from that period

## 4. WHO MODIFIED THE CRON

The dropper script **cleaned** the crontab (removing lines containing "rbfeeder"), it did not add malicious entries. This mechanism erases traces of previous attack versions that used crontab for persistence.

No system crontab contains malicious entries. Malware persistence relies exclusively on the systemd service `upev.service`.


## 5. SERVER INFRASTRUCTURE, DOMAINS, RAT FILES

**Domain:** `apt.TransponderLive.org` (registered to look like a legitimate APT repository)

The infrastructure consists of 4 servers, all on Alibaba Cloud (Asia), plus a fallback server on Vultr:

| IP | Ports | Function |
|----|-------|----------|
| `47.91.75.121` | 80, 58888 | HTTP dropper server (RAT binary and installation script distribution) |
| `47.245.129.80` | 443 | C2 HTTPS server (receiving encrypted beacons from infected devices) |
| `8.219.81.242` | 7000 | FRP server for ADS-B data tunneling |
| `47.89.154.27` | 7700 | Secondary FRP server (admin proxy, SOCKS5, internal network access) |
| `45.63.1.41` | n/a | Vultr, fallback rbfeeder server |

> **NOTE:** The secondary FRP server (`47.89.154.27`) contains configurations to reach internal network addresses (`10.0.10.56`), which indicates the compromise of devices within corporate private networks.

## 6. C2 PROTOCOL (COMMAND & CONTROL)

The malware uses a sophisticated communication system:

**DNS Resolution:**
The malicious binary does not use system DNS but makes direct queries to Google (`8.8.8.8`) and Cloudflare (`1.1.1.1`) to resolve the domain `apt.TransponderLive.org`. Additionally, standard DNS results and internal ones point to different IPs, a technique to make tracking more difficult.

**Encryption:**
Communication with the C2 server is encrypted with **AES-256-CBC**. The key is derived from the device serial number, so each infected device has a unique key.

**Communication:**
The RAT periodically sends system information to the C2 server (via HTTPS): serial number, hostname, IP, architecture, OS version. The server can respond with commands, including the ability to open an interactive remote shell on the device.


### 6.1 HTTP DROPPER SERVER CONTENTS

Server mirror performed on April 18, 2026. The site has directory listing enabled and contains:

```
http://47.91.75.121/
│
├── c                          clean crontab (replacement)
├── upev                       init.d script for upev
├── upev.service               systemd unit for upev
│
├── /08967/frp/                directory with FRP client and configs
│   ├── adm                    FRP config → admin proxy
│   ├── dump987                FRP client x86-64 (renamed for camouflage)
│   ├── frpc_arm               FRP client ARM32
│   ├── frpc_x64               FRP client x86-64
│   ├── readadsb               FRP config → SOCKS5 proxy
│   ├── sock5.toml             FRP config → SOCKS5 proxy
│   └── sql                    FRP config → internal database proxy
│
├── /494/                      staging area (dropper + config)
│   ├── frpc_arm               FRP client ARM32
│   ├── ip                     FRP server IP (gzip)
│   ├── rbfeeder.sh            installation dropper script (gzip)
│   └── sock5.toml             SOCKS5 config
│
├── /a/                        campaign "a", generic ADS-B feeder
│   ├── amd64 / arm / arm64 / armv6l     RAT binaries (UPX packed)
│   └── *.md5                             hashes for update check
│
├── /e/                        campaign "e", unknown
├── /k/                        campaign "k", KiwiSDR
├── /n/                        campaign "n", unknown
├── /r/                        campaign "r", RadarCape
├── /u/                        campaign "u", unknown
│   └── (same structure: 4 binaries + 4 MD5 per campaign)
│
├── /tmp/                      staging area (= /494/)
│
└── /files/                    empty directories (future staging?)
    ├── /a/, /e/, /k/, /n/, /r/, /tmp/, /u/  (all empty)

TOTAL: 66 files, 17 directories, ~280 MB
```

*The credentials to authenticate on the site were found in the configuration files sent with the RAT.*


### 6.2 MALWARE CAMPAIGNS (6 VARIANTS)

The server distributes the RAT in 6 different "campaigns", each targeting a specific device type:

| Campaign | Target |
|----------|--------|
| **a** | Default (generic ADS-B feeder) |
| **e** | Unknown |
| **k** | KiwiSDR (web SDR receiver) |
| **n** | Unknown |
| **r** | RadarCape (dedicated ADS-B receiver) |
| **u** | Unknown |

Each campaign has binaries for 4 hardware architectures, all UPX-packed. The binaries differ slightly between campaigns (likely with device-type-specific configuration).


### 6.3 FRP CONFIGURATIONS (4 TUNNEL PROFILES)

Four FRP tunnel configuration profiles were found on the server, allowing the attacker to:
- Use infected devices as **SOCKS5 proxies** (anonymous browsing)
- Access remote **admin panels**
- Reach **internal databases** on private networks (`10.x.x.x`)

The FRP client is disguised as `dump987` or `dump1090-rb` to appear as a legitimate ADS-B decoding process.

## 7. ACCESS TO THE C2 INFRASTRUCTURE (April 2026)

The HTTP dropper server (`47.91.75.121`) is accessible with hardcoded credentials found in the malicious script. Directory listing is enabled, allowing enumeration of all distributed files.

The C2 HTTPS server (`47.245.129.80`) receives encrypted beacons from infected devices. Encryption uses AES-256-CBC with a key derived from the device serial number.

The FRP server (`8.219.81.242`) creates TCP tunnels for ADS-B data exfiltration. The FRP authentication token is hardcoded in the malicious binary.

**Credentials and access found:**
- **HTTP dropper:** Basic Auth with credentials hardcoded in the script
- **FRP relay:** authentication token hardcoded in the binary
- **Beacon encryption:** key derived from device serial number
- **C2 domain:** `apt.transponderlive.org`


## 8. FRP MECHANISM: DATA TUNNELING

Once active, the RAT downloads an FRP (Fast Reverse Proxy) client from the C2 server, saves it as `/tmp/dump1090-rb` (name chosen to blend in with the legitimate dump1090) and starts it.

The FRP tunnel exposes local port **30005** (where dump1090-fa serves ADS-B data in Beast format) to a remote server. Anyone connecting to the FRP server on the assigned port receives the real-time radar data stream from the device (to what end??).

This tunnel is for ADS-B data exfiltration. The RAT **ALSO** has interactive remote shell capabilities, but those go through the separate C2 HTTPS channel.


## 9. THE MALICIOUS INSTALLATION SCRIPT (rbfeeder.sh)

The dropper script, downloaded from the C2 server and analyzed, does the following:

1. Determines the system architecture and geographic continent
2. Resolves the C2 domain bypassing local DNS (uses DNS over HTTPS)
3. Downloads the appropriate RAT binary for the device architecture

**If run as ROOT** (rbfeeder's case):
- Installs the binary as `/usr/bin/upevm`
- Creates a symlink `/usr/bin/upev`
- Registers a systemd service disguised as "udev" (device management)
- Cleans traces from crontab
- Deletes itself

**If run as a normal user:**
- Saves the binary in a hidden directory (`/tmp/.font-unix/`)
- Adds a crontab entry for persistence (re-downloads every minute if not active)

On my Pi, rbfeeder runs as ROOT → the maximum-privilege path was executed (did they ever try to attack something on my internal network?).


## 10. AIRNAV RBFEEDER AND ITS COMMAND EXECUTION CAPABILITY

> **Analysis methodology:** rbfeeder's behavior was analyzed using **exclusively** standard Linux tools, without reverse engineering the binary:
> - `readelf` showed that the program imports the `posix_spawn` function (used to spawn child processes)
> - `strings` extracted readable text strings from the binary
> - `strace` confirmed that rbfeeder spawns child processes in real time
> - `ss`/`netstat` showed the active connection to the AirNav server

**Results:**

From the strings and imported symbols, it is clear that rbfeeder has the capability to receive commands from the server via the proprietary protocol and execute them as system shell commands. The strings indicate a structured mechanism: the server sends a command, rbfeeder receives it (`"Expected CMD has arrived!"`) and executes it via `posix_spawn("/bin/sh", "-c", <command>)`.

Key strings found:
- `"Run command: %s"`
- `"/bin/sh"`
- `"Expected CMD has arrived!"`
- `"posix_spawn: %s"`
- `"WaitCMD done!"`

The program waits for commands from the server. Commands are executed silently: **they are never written to the log file**.

**Confirmed active connections:**
- Connection to the AirNav server (`212.224.72.114:33755`)
- Local connection to dump1090 (port 30005)
- Local connection to the MLAT client

## 11. SUMMARY: REMOTE EXECUTION CAPABILITIES

From the imported symbols and strings of the rbfeeder binary, it emerges that:

- The server has the capability to **execute commands on every connected rbfeeder**
- In **v0.3.5** (installed on the Pi): commands are executed with full system compromise
- In **v1.0.15** (latest version): commands are executed as the dedicated `rbfeeder` user, mitigated but still significant
- There is no validation or signing of received commands
- v0.3.5 **does not use encryption** on the communication channel
- An attacker intercepting network traffic could inject commands (man-in-the-middle attack)


## 12. RBFEEDER: DIFFERENCES BETWEEN VERSIONS

Version v1.0.15 (the most recent) has some significant differences compared to v0.3.5 installed on my Pi:

- Runs as a dedicated `rbfeeder` user instead of root
- The Debian package **postinst** script (which runs as root during `apt install`) contains **anti-malware code** that actively searches for and removes transponderlive campaign files and processes

This last point is particularly significant: the installation script, running with root privileges, specifically looks for transponderlive malware files and processes and removes them. Note: this cleanup only happens at package installation/upgrade time, not during normal rbfeeder operation (which, running as an unprivileged user, would not have permission to kill root processes or delete system files).

However, **the remote command execution mechanism remains present** in v1.0.15 as well: the capability is still there, just with reduced privileges.


## 13. CONCLUSION

Four main hypotheses with a common assumption:

> The remote command execution mechanism is an **INTENTIONAL FEATURE** of rbfeeder, not a vulnerability discovered by third parties.

**Hypothesis 1:** AirNav Systems (RadarBox) did it on purpose *(I rule this out)*

**Hypothesis 2:** Someone compromised the RadarBox infrastructure and, finding this remote execution capability, exploited it to distribute the malware

**Hypothesis 3:** An AirNav employee or contractor, with inside knowledge of the system, abused their access to create a parallel ADS-B data interception campaign

**Hypothesis 4:** Communication between rbfeeder and the server happens over an insecure connection. Someone could have compromised the DNS server by changing the IP, redirecting connections to a fake server which then used the RCE present in the system (which includes no protection whatsoever)

---

### Personal opinion

The command execution mechanism was undoubtedly built in by AirNav. Perhaps they wanted a remote management channel for their devices, but in doing so they created a backdoor on all devices of unsuspecting users.

**AirNav IS AWARE of the malware campaign**, the proof is that later versions of their software contain specific code to search for and remove the transponderlive malware. This demonstrates they know about the problem, but they never warned their users (I never received any warning email).

The RAT campaign also appears to target RadarCape and KiwiSDR, which suggests they have access to other devices as well.

A word of advice: if you have any of these software packages running on any device, take a look at what's actually running... ;-)