# SOC Investigation : Windows Mass Defacement

It is a bright sunny morning and my second week in office as a SOC Analyst. My first job and my dream role.  Over the course of a week I took my time understanding the network map of my company.

<img src="images/network map.png" alt="nm" width="800"/>

The network is split into 7 zones and each with its own subnet:

- **DMZ Segment (172.16.100.0/24)** -- every public web server lives here including a handful of websites, a mail relay, and DMZ-DNS. This is the zone the internet touches.
- **Server Segment (192.168.200.0/24)** -- internal infrastructure: domain controller, internal DNS, Exchange, file server.
- **User Segment (192.168.100.0/24)** — regular employee workstations.
- **SOC Segment (192.168.110.0/24)** — analyst workstations and dedicated forensics and Remnux boxes.
- **SIEM Segment (192.168.66.0/24)** — Splunk, QRadar, Security Onion, Rsyslog.
- **Customer and DB Segments** — separate subnets for customer-facing workstations and the database tier.
- **OT Segment** — sits behind its own dedicated OT firewall, fully separated from everything else.

Two firewalls: a **DMZ Firewall** sits between the internet router and the DMZ, and a **Central Firewall** sits between the DMZ and every internal segment (Server, SIEM, User, SOC, Customer, DB), with a separate leg for the OT segment.

## The Day of my first investigation

I am just sipping the first coffee of the day preparing to start work, when I receive a call. "Umm, Hi. It looks like there is a problem with your website nbc.com, it has a strange message on the front page. I think you should check it out." At first I really believed that it was a prank. I still plan to check it out and casually type n--b--c--.--c--o--m --- ENTER in the browser. And there it was..

<img src="images/defaced website.png" alt="defaced website" width="800"/>

## Scenario

I panicked, it was real. I try to assess the severity and get an idea of how deep the attacker might have already gone.

nbc.com lives in the DMZ, so a defacement there, on paper, is contained to a public-facing zone, it does not mean the internal network is compromised. So my working assumption going in was "worst case, this is isolated to one public-facing server."

I had to test my assumption. The only way to know was to go check what else was running on that box. But first, who do I call?

### So who do you actually call?

In that moment, my first instinct was to just log in and start poking around. But if this turned into an actual investigation, anything I touched could mess with timestamps, active sessions, whatever the attacker left behind. So instead, I picked up the phone.

I learned pretty fast that the "who do I call" order is not obvious when you are new. Gathering all the knowledge I had from seeing and writing various playbooks over the years, I decided to inform the IR lead. They confirmed it was worth pursuing and handed the technical digging to me: since I was the one who first spotted it. They stayed on for the comms and containment calls; the investigation below is what I did after that handoff.

## Approach

So I first start off by dropping inbound traffic at the firewall instead of killing the server outright, which kept the evidence intact while still stopping the defacement from being visible to the public.

<img src="images/block victim.png" alt="block victim" width="700"/>
<img src="images/drop v deny.png" alt="drop v deny" width="700"/>

### Drop vs. Deny

Here is something I learned while doing this:

Both stop traffic, but they don't stop it the same way:

- **Drop**: the packet is discarded silently. No response is sent back to the source. From the attacker's side, it just looks like the target isn't there.
- **Deny/Reject**: the packet is refused, but the firewall sends something back (like a TCP reset or ICMP "unreachable"). The attacker gets confirmation something is there, actively blocking them.

For recon-stage attackers, **drop is usually preferred** - it doesn't confirm the host exists, so it doesn't help them refine their scan. Deny is more useful when you *want* the source to know a rule exists.

### Reconnaissance (MITRE ATT&CK TA0043)

I see past activity on this server. I open Security Onion and go through the logs. And what do I see? A port scan against the server (130.2.2.12) to identify exposed services.

<img src="images/recon nmap.png" alt="recon nmap" width="900"/>

**Technique:** T1595 -- Active Scanning

### Initial Access & Credential Access (TA0001 / TA0006)

But what was open? I open Splunk and see the logs.

 - Step 1: search for the deface message in logs
```
index=* "Look ma, no security! DOH!"
```
- Step 2: filter all successful and failed logons on the target host
```
index=* host="WebServer-IIS" EventCode=4624 --> (successful)
index=* host="WebServer-IIS" EventCode=4625 --> (failed)
```
- Step 3: see what logon types are present
```
index=* host="WebServer-IIS" EventCode=4624
| stats count by Logon_Type
```
- Step 4: filter down to RDP logons only (type 10)
```
index=* host="WebServer-IIS" EventCode=4624 Logon_Type=10
```
- Step 5: identify the external IP
```
index=* host="WebServer-IIS" EventCode=4624 Logon_Type=10
| table _time, Account_Name, Logon_Type, Source_Network_Address, Workstation_Name
| sort _time
```

I see a remote login through an external IP. Port 3389(Remote Desktop Protocol) was open. They ran a brute force attack against the RDP service and eventually succeeded with logging in as Administrator because the password was weak.

Once I confirmed RDP was the way in and passwords were weak across the network, I thought it would not hurt to scan the rest of the environment for RDP exposure. I found two other machines with the same problem, the attacker accessed them too and they were web servers as well. When I double checked, those websites were defaced too. That changed the scope of the investigation: this wasn't just "one defaced web server," it was a pattern of exposed RDP that needed to get flagged and locked down environment-wide. I dropped the inbound traffic for those websites as well.

<img src="images/logontype values.png" alt="logontype values" width="500"/>
<img src="images/remote SIEM log.png" alt="remote SIEM log" width="500"/>
<img src="images/remote logins.png" alt="remote logins" width="800"/>

**Techniques:** T1110.001 -- Brute Force: Password Guessing --> T1078 - Valid Accounts --> T1021.001 -- Remote Services: RDP

---

### Execution & Discovery (TA0002 / TA0007)

When I analyzed the SIEM log, this is what I noticed: PowerShell script block logging (EventID 4104, `Microsoft-Windows-PowerShell/Operational`) had captured the exact command the attacker ran - `echo 'Look ma, no security! DOH!' > 'c:\inetpub\wwwroot\index.aspx'`, on `WebServer-IIS`. That is the command that produced the message I'd seen on the front page that morning. Also confirmed this via a Security Onion Powershell alert. That is what sent me straight to the console history.

Path to console history: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

<img src="images/console history.png" alt="console history" width="700"/>

What commands were executed? The attacker downloaded two files: a `.ps1` and a `.bat` to `C:\ProgramData`.

<img src="images/attacker scripts.png" alt="attacker scripts" width="500"/>

The PowerShell file was a C2 implant/backdoor staged in `ProgramData`. It checks in with a remote server via HTTP POST to receive a session key, then compresses and Base64-encodes data before exfiltrating it back.

<img src="images/powershell script.png" alt="powershell script" width="800"/>

I went back to Security Onion to confirm the implant was already running, and it was. Suricata had been firing "ET INFO Windows Powershell User-Agent Usage" alerts from `172.16.100.30` outbound to `9.53.99.47` (the C2 server) every 9-10 seconds consistently. That is the beaconing pattern of the implant checking in, and Suricata caught it because PowerShell's default HTTP user agent on the outbound POST requests matches a known detection signature.

<img src="images/security onion powershell alert.png" alt="security onion powershell alert" width="700"/>

<img src="images/batch file.png" alt="batch file" width="900"/>

The batch file is a plain-text script executed sequentially by cmd.exe. It generated `enum.txt` that had a full system and network enumeration, everything an attacker needs to understand what they've landed on.

**Techniques:**

- T1059.001 – PowerShell
- T1082 – System Information Discovery / T1016 – System Network Configuration Discovery
- T1132.001 – Standard Encoding (Base64)
- T1560 – Archive Collected Data
- T1071.001 – Application Layer Protocol: Web Protocols
- T1041 – Exfiltration Over C2 Channel

### Impact (TA0040)

<img src="images/exfil data.png" alt="exfil data" width="800"/>
<img src="images/defaced html pages.png" alt="defaced html pages" width="700"/>

**Technique:** T1491.001 – Defacement: External Defacement

### The warez twist

The console history also shows the attacker created a directory called `asdf`. Investigating it, I found a folder full of files staged inside `C:\inetpub\wwwroot\asdf`, which meant all of them were directly HTTP-accessible by clicking the URL.

It looked like piracy at first -- a movie, some cracks and keygens. Then Security Onion logs showed a stream of external IPs downloading these files. The attacker was using our compromised server as a free distribution host. But I noticed a bit later that this wasn't just warez:

- `HacktotheFuture-full-movie.mp4` - pirated film
- `AdobeSerialGenerator.exe`, `keygen.exe`, `windows10_full_crack.exe` - software cracking tools
- `keylogger.dll` - actual malware
- `encryptAll.elf` - Linux ELF binary
- `PasswordSniffer.apk` - Android credential harvester
- `MACSwitcher.bin` / `MACSwitcherWin.exe` - MAC address spoofing tools
- `hide_my_ip.ovpn` - an OpenVPN config
- `collection.zip` - 29MB archive of unknown contents

<img src="images/warez in target.png" alt="warez in target" width="800"/>
<img src="images/warez downloads.png" alt="warez downloads" width="800"/>

Someone downloading what they think is a keygen or a cracked copy of Windows is actually getting a keylogger or a password sniffer. The attacker was using our server's clean IP reputation to distribute malware disguised as cracked software - because a download from an established business server is far less likely to get flagged by endpoint security or ISPs than one from an unknown host.

## Detection Rules
Here are the detection rules I wrote after this incident. Had these been in place earlier, we would have caught this attack well before it progressed as far as it did.
### RDP Brute Force
 
Multiple failed RDP logons from the same source IP within a short window.
 
```spl
index=* EventCode=4625 Logon_Type=10
| bucket _time span=5m
| stats count as FailedAttempts by _time, Source_Network_Address, ComputerName
| where FailedAttempts > 10
| table _time, Source_Network_Address, ComputerName, FailedAttempts
```
 
### Successful RDP Login After Brute Force
 
Same external IP that failed repeatedly then succeeds — the exact pattern from this investigation.
 
```spl
index=* EventCode=4624 OR EventCode=4625 Logon_Type=10
| stats count(eval(EventCode=4625)) as Failures, 
        count(eval(EventCode=4624)) as Successes 
        by Source_Network_Address, ComputerName
| where Failures > 10 AND Successes > 0
| table Source_Network_Address, ComputerName, Failures, Successes
```
 
### C2 Beaconing
 
Regular interval outbound PowerShell HTTP traffic — what Suricata was already catching, now as a Splunk rule.
 
```spl
index=* rule.name="ET INFO Windows Powershell User-Agent Usage"
| bucket _time span=1m
| stats count as Beacons by _time, src_ip, dest_ip
| where Beacons > 5
| table _time, src_ip, dest_ip, Beacons
```

## Mitigation and Recovery 
- **Block the attacker's IP** at the firewall, both inbound and outbound, to cut off any active C2 communication and prevent re-entry.
- **Require VPN for RDP** - RDP should only be reachable from inside the network or over a VPN tunnel.
- **Disable RDP on hosts that don't need it**
- **Enable MFA on all remote access.**
- **Enable account lockout policies** - lock the account after a set number of failed attempts.
- **Remove write access to `wwwroot`** - the web server process should never have had permissions to write files into `inetpub\wwwroot`. Restricting write access means even a compromised session can't drop or modify web content.
- **Delete all attacker-dropped files** 
- **Rotate the Administrator password** on all affected machines, and audit whether weak passwords exist elsewhere in the environment.
- **Restore the defaced websites** from a known-clean backup.
 
 ## Lessons Learned
The biggest thing I took away from this investigation is how a single exposed port and a weak password can turn into a full compromise. I found the attacker IP in the first 10 minutes, but the real challenge was understanding how far they had already gone. I had initially assumed that one defaced website on the DMZ could not mean anything too serious. I was wrong. Once I started analysing the logs there was a full blown warez distribution system up and running, a C2 implant beaconing out, and two other defaced web servers I had not even looked at yet. If I had to do this again I would scan the rest of the environment for RDP exposure the moment I confirmed it was the attack vector, not after I had already finished investigating the first host. What this incident showed me about real SOC work is that the alert is just the starting point. You have to follow it all the way through, because what is sitting underneath the obvious finding is usually the bigger problem.
