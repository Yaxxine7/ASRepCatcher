# ASRepCatcher - Make everyone in your VLAN ASREProastable


During an Active Directory black box pentest, if multicast DNS protocols are disabled and/or all protocols (SMB, LDAP, etc.) are signed and no exposed service is vulnerable, you quickly run out of options to get a domain user.


ASRepCatcher uses ARP spoofing to catch AS-REP messages returned by the Domain Controller to the clients and prints out the hash to crack.

**This technique does not rely on Kerberos pre-authentication being disabled. It works for all users on the VLAN.**

## Two modes


### Relay

**This is the preferred way.**<br>
In relay mode, the Kerberos TGT requests (AS-REQ) coming from workstations are relayed to the DC. <ins>If RC4 is allowed, the clients are forced to use it.</ins><br>
If ARP spoofing is enabled, the ARP caches of the workstations are poisoned in order to catch the AS-REQ requests.

```bash
ASRepCatcher relay -dc 192.168.1.100
```
### Listen

In listen mode, the ARP cache of the gateway is poisoned in order to receive the AS-REP responses destined to the clients.
This is a passive mode, there is no alteration of the packets in transit.

```bash
ASRepCatcher listen
```
<br><ins>Bonus</ins> : The tool catches unseen usernames in TGS-REP responses in order to give the attacker more information about the domain.

## Features of ARP spoofing
In both ways, the arp spoofing is <ins>never in full-duplex : only one way is targetted</ins>. The purpose of this is to reduce network load on the attacker host.

If executed with *--stop-spoofing* option, a **client computer's IP is removed from the list** whenever a hash is retrieved from the IP :<br>
- In relay mode, the client's ARP cache is restored.
- In listen mode, the entry in the gateway's ARP cache is restored

<ins>It is better not to use the *--stop-spoofing* option as there can be in a lot of cases, many users on the same IP (mutualized computers, DHCP, NAT, etc.)</ins><br>
If you prefer to use your own spoofing method, you can disable ARP spoofing with *--disable-spoofing*.

## Installation

```bash
python3 -m pip install ASRepCatcher
```
OR
```bash
git clone https://github.com/Yaxxine7/ASRepCatcher
cd ASRepCatcher
python3 setup.py install
```
Requires at least Python 3.7
## Usage

```
            _____ _____             _____      _       _               
     /\    / ____|  __ \           / ____|    | |     | |              
    /  \  | (___ | |__) |___ _ __ | |     __ _| |_ ___| |__   ___ _ __ 
   / /\ \  \___ \|  _  // _ \ '_ \| |    / _` | __/ __| '_ \ / _ \ '__|
  / ____ \ ____) | | \ \  __/ |_) | |___| (_| | || (__| | | |  __/ |   
 /_/    \_\_____/|_|  \_\___| .__/ \_____\__,_|\__\___|_| |_|\___|_|   
                            | |                                        
                            |_|                                     
Author : Yassine OUKESSOU
Version : 0.4.0
                            
usage: ASRepCatcher [-h] [-outfile OUTFILE] [-format {hashcat,john}] [-debug] [-t Client workstations] [-tf targets file] [-gw Gateway IP] [-dc DC IP] [-iface interface]
                    [--stop-spoofing] [--disable-spoofing]
                    {relay,listen}

Catches Kerberos AS-REP packets and outputs it to a crackable format

positional arguments:
  {relay,listen}        Relay mode  : AS-REQ requests are relayed to capture AS-REP. Clients are forced to use RC4 if supported.
                        Listen mode : AS-REP packets going to clients are sniffed. No alteration of packets is performed.

options:
  -h, --help            show this help message and exit
  -outfile OUTFILE      Output filename to write hashes to crack.
  -usersfile USERSFILE  Output file name to write discovered usernames.
  -format {hashcat,john}
                        Format to save the AS_REP hashes. Default is hashcat.
  -debug                Increase verbosity
  -dc DC IP             Domain controller's IP.
  -iface interface      Interface to use. Uses default interface if not specified.

ARP poisoning:
  -t Client workstations
                        Comma separated list of client computers IP addresses or subnet (IP/mask). In relay mode they will be poisoned. In listen mode, the AS-REP directed to them are captured. Default is whole subnet.
  -tf targets file      File containing client workstations IP addresses.
  -gw Gateway IP        Gateway IP. More generally, the IP from which the AS-REP will be coming from. If DC is in the same VLAN, then specify the DC's IP. In listen mode, only this IP's ARP cache is poisoned. Default is default interface's gateway.
  --stop-spoofing       Stops poisoning the target once an AS-REP packet is received from it. False by default.
  --disable-spoofing    Disables arp spoofing, the MitM position is attained by the attacker using their own method. False by default : the tool uses its own arp spoofing method.
```
## Demo
![Capture vidéo du 2024-03-28 01-09-53](https://github.com/Yaxxine7/ASRepCatcher/assets/110096329/7364bfd6-345a-405d-b519-f2af3cc39a25)
