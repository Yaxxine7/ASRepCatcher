# ASrepCatcher
Make everyone in your VLAN ASREProastable


During an Active Directory black box pentest, if multicast DNS protocols are disabled and/or all protocols (SMB, LDAP, etc.) are signed and no exposed service is vulnerable, you quickly run out of options to get a domain user.


ASRepCatcher uses ARP spoofing to catch AS-REP messages returned by the Domain Controller to the clients and prints out the hash to crack.


## Two modes

### Listen

This is the preferred way.
In listen mode, the ARP cache of the gateway is poisoned in order to receive the AS-REP responses destined to the clients.

```bash
./ASrepCatcher.py listen
```
<ins>Bonus</ins> : in listen mode, the tool catches usernames in TGS-REP responses in order to give the attacker more information about the domain.
### Replay

This mode should be used if the gateway has ARP spoofing protections.
In replay mode, the ARP caches of the clients are poisoned in order to catch the AS-REQ requests. They are then replayed to the DC.

```bash
./ASrepCatcher.py replay
```

## Features of ARP spoofing
In both ways, the arp spoofing is <ins>never in full-duplex : only one way is targetted</ins>. The purpose of this is to reduce network load on the attacker host.

Unless executed with *--keep-spoofing* option, a **client computer's IP is removed from the list** whenever a hash is retrieved from the IP :<br>
- In replay mode, the client's ARP cache is restored.
- In listen mode, the entry in the gateway's ARP cache is restored

If you prefer to use your own spoofing method, you can disable ARP spoofing with *--disable-spoofing*.

## Usage

```
            _____ _____             _____      _       _               
     /\    / ____|  __ \           / ____|    | |     | |              
    /  \  | (___ | |__) |___ _ __ | |     __ _| |_ ___| |__   ___ _ __ 
   / /\ \  \___ \|  _  // _ \ '_ \| |    / _` | __/ __| '_ \ / _ \ '__|
  / ____ \ ____) | | \ \  __/ |_) | |___| (_| | || (__| | | |  __/ |   
 /_/    \_\_____/|_|  \_\___| .__/ \_____\__,_|\__\___|_| |_|\___|_|   
                            | |                                        
                            |_|                                          by Yassine OUKESSOU


                            
usage: ASrepCatcher.py [-h] [-t Client computers] [-tf TF] [-gw GW] [-outfile OUTFILE] [-format {hashcat,john}] [-iface IFACE] [--keep-spoofing] [--disable-spoofing] {listen,replay}

Catches Kerberos AS-REP packets and outputs it to a crackable format

positional arguments:
  {listen,replay}       Listen mode : Only the gateway's ARP cache is poisonned, AS-REP packets going to clients are sniffed
                        Replay mode : Only the client computers' ARP caches are poisonned, AS-REQ requests are replayed to capture AS-REP

options:
  -h, --help            show this help message and exit
  -t Client computers   Comma separated list of client computers IPs or subnet (IP/mask). In replay mode they will be poisoned. In listen mode, the AS-REP directed to them are captured. Default is whole subnet
  -tf TF                File containing targets
  -gw GW                Gateway IP. More generally, the IP from which the AS-REP will be coming from. If DC is in the same VLAN, then specify the DC's IP. Only this IP is poisoned in listen mode. Default is default interface's gateway
  -outfile OUTFILE      Output filename to write hashes to crack
  -format {hashcat,john}
                        Format to save the AS_REQ of users without pre-authentication. Default is hashcat
  -iface IFACE          Interface to use. Uses default interface if not specified
  --keep-spoofing       Keeps poisoning the targets after capturing AS-REP packets. False by default
  --disable-spoofing    Disables arp spoofing, the MitM position is attained by the attacker using their own method. False by default : the tool uses its own arp spoofing method
```

