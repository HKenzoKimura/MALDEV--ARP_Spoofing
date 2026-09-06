# ☠️ ARP Poisoner + Packet Sniffer — Python / Scapy

> **Context:** Man-in-the-Middle (MITM) tool built with Scapy for network security research and lab environments. Combines **ARP cache poisoning** with **packet capture** to intercept and log traffic between a target host and its gateway — demonstrating the attack chain from initial positioning to traffic collection and cleanup.
>
> ⚠️ *Use only in networks onde você tem autorização explícita. ARP poisoning em redes sem permissão é crime.*

---

## `$ cat ./objective.txt`

Demonstrar o ciclo completo de um ataque **ARP Spoofing / MITM**:

1. **Reconhecimento** — descobrir os endereços MAC de vítima e gateway via ARP request legítimo
2. **Posicionamento** — envenenar as tabelas ARP de ambos, redirecionando o tráfego pelo atacante
3. **Coleta** — capturar pacotes da vítima com filtro BPF e salvar em `.pcap`
4. **Cleanup** — restaurar as tabelas ARP ao estado original após a captura

---

## `$ cat ./how_arp_works.txt`

### O Protocolo ARP e por que é vulnerável

**ARP (Address Resolution Protocol)** resolve endereços IP em endereços MAC na camada 2. Quando um host precisa se comunicar com `192.168.1.1`, ele faz um broadcast perguntando:

```
"Quem tem 192.168.1.1? Me diga 192.168.1.50"
ARP Request → dst: ff:ff:ff:ff:ff:ff (broadcast)
              op:  who-has (1)
              pdst: 192.168.1.1
```

O gateway responde:
```
ARP Reply → op:  is-at (2)
            psrc: 192.168.1.1
            hwsrc: aa:bb:cc:dd:ee:ff   ← MAC real do gateway
```

**A vulnerabilidade:** ARP é **stateless e não autenticado**. Qualquer host pode enviar um ARP Reply sem ter recebido um Request, e os sistemas aceitam a resposta e atualizam sua tabela ARP (cache) sem verificação. Isso é o ARP Spoofing.

---

## `$ cat ./attack_flow.txt`

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       ARP POISONING — MITM FLOW                         │
│                                                                         │
│   ANTES DO ATAQUE:                                                      │
│   Vítima  ←──────────────────────────────────────────►  Gateway        │
│            tráfego direto (MAC real do gateway na ARP cache)            │
│                                                                         │
│   APÓS O ENVENENAMENTO:                                                 │
│                                                                         │
│   Vítima  ──────────►  ATACANTE  ──────────────────►  Gateway          │
│           (pensa que      │        (pensa que                           │
│           atacante =      │        atacante =                           │
│           gateway)        │        vítima)                              │
│                           │                                             │
│                      Captura pcap                                       │
│                      Inspeciona dados                                   │
│                                                                         │
│   PACOTES FORJADOS ENVIADOS CONTINUAMENTE (a cada 2s):                  │
│                                                                         │
│   → Para a VÍTIMA:   "O gateway (192.168.1.1) está em [MAC atacante]"  │
│   → Para o GATEWAY:  "A vítima  (192.168.1.50) está em [MAC atacante]" │
│                                                                         │
│   PROCESSO PARALELO:                                                    │
│   ┌─────────────────────┐    ┌──────────────────────────────────────┐  │
│   │  poison (Process 1) │    │  sniff_packets (Process 2)           │  │
│   │  loop ARP a cada 2s │    │  captura 100 pkts → arper.pcap       │  │
│   │  até CTRL-C         │    │  depois: restore() automático        │  │
│   └─────────────────────┘    └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## `$ cat ./design_decisions.md`

### 1. `get_mac()` — ARP Discovery com `srp()`

```python
packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op='who-has', pdst=targetip)
resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
```

**Por que `srp()` e não `sr()`?**

- `sr()` opera na camada 3 (IP); `srp()` opera na camada 2 (Ethernet) — necessário para ARP, que vive na L2
- O pacote é encapsulado como `Ether/ARP`: o frame Ethernet com dst broadcast garante que todos os hosts da rede processem o ARP Request
- `retry=10` lida com ambientes com perda de pacotes ou hosts que demoram para responder

**Extração do MAC:**
```python
for _, r in resp:
    return r[Ether].src   # MAC real do host que respondeu
```

O MAC vem do campo `src` do frame Ethernet de resposta — não do campo `hwsrc` do ARP, que poderia ser forjado.

---

### 2. `poison()` — Envenenamento Bidirecional

Para que o atacante fique no meio do tráfego, **ambos os lados** precisam ser envenenados simultaneamente. Envenenar apenas a vítima redireciona o tráfego de saída, mas a resposta do gateway chegaria diretamente à vítima — não ao atacante.

```
poison_victim:   ARP Reply → vítima
                 psrc = IP do gateway   ← mentira
                 hwsrc = MAC atacante   ← mentira (preenchido automaticamente pela NIC)
                 "Ei vítima, o gateway está no MEU MAC"

poison_gateway:  ARP Reply → gateway
                 psrc = IP da vítima    ← mentira
                 hwsrc = MAC atacante   ← mentira
                 "Ei gateway, a vítima está no MEU MAC"
```

**Por que `op=2` (is-at)?**

ARP `op=1` é Request (pergunta), `op=2` é Reply (resposta). Os sistemas aceitam Replies mesmo sem ter feito uma pergunta — essa é a raiz da vulnerabilidade.

**Loop com `time.sleep(2)`:**

As tabelas ARP têm TTL (geralmente 60-300 segundos no Linux/Windows). O envio periódico a cada 2 segundos garante que as entradas envenenadas sejam renovadas antes de expirar e o tráfego retornar ao caminho original.

---

### 3. `sniff_packets()` — Captura com Filtro BPF

```python
bpf_filter = "ip host %s" % victim
packets = sniff(count=count, filter=bpf_filter, iface=interface)
wrpcap('arper.pcap', packets)
```

**O que é um filtro BPF?**

Berkeley Packet Filter — linguagem de filtragem implementada no kernel que descarta pacotes irrelevantes *antes* de chegarem ao espaço do usuário. Isso é muito mais eficiente do que capturar tudo e filtrar em Python.

`"ip host 192.168.1.50"` captura apenas pacotes IP onde a vítima é source **ou** destination — o tráfego intercedido que passa pelo atacante.

**`wrpcap()`** salva em formato `.pcap` — compatível com Wireshark, tshark, tcpdump para análise posterior.

---

### 4. `restore()` — Limpeza Responsável

```python
send(ARP(op=2, psrc=gateway, hwsrc=gatewaymac, pdst=victim,   hwdst='ff:ff:ff:ff:ff:ff'), count=5)
send(ARP(op=2, psrc=victim,  hwsrc=victimmac,  pdst=gateway,  hwdst='ff:ff:ff:ff:ff:ff'), count=5)
```

Envia ARP Replies **verdadeiros**, anunciando os MACs reais de gateway e vítima para ambos os lados. `count=5` garante que pelo menos um pacote seja recebido mesmo em redes com perda. `hwdst='ff:ff:ff:ff:ff:ff'` (broadcast) garante que todos os hosts na rede atualizem suas caches — útil se outros hosts também foram afetados.

Sem o restore, a vítima fica sem acesso à rede até que a ARP cache expire naturalmente.

---

### 5. `multiprocessing.Process` — Por que não threads?

```python
poison_thread = Process(target=poison, ...)
sniff_thread  = Process(target=sniff_packets, ...)
```

O Python tem o **GIL (Global Interpreter Lock)** — apenas uma thread executa bytecode Python por vez. Para operações de I/O de rede intensivo como captura de pacotes com Scapy, o GIL causaria contenção entre o loop de envenenamento e o sniffer.

`multiprocessing.Process` cria **processos separados** (cada um com seu próprio interpretador e GIL), permitindo execução verdadeiramente paralela — o envenenamento contínuo não bloqueia a captura e vice-versa.

---

## `$ cat ./mitre_mapping.yml`

```yaml
tactics:
  collection:
    - T1040      # Network Sniffing
                 # Captura de pacotes via sniff() + wrpcap() → arper.pcap

  credential_access:
    - T1557.002  # Adversary-in-the-Middle: ARP Cache Poisoning
                 # Envenenamento bidirecional vítima ↔ gateway

  discovery:
    - T1018      # Remote System Discovery
                 # get_mac() descobre hosts ativos via ARP who-has
    - T1590.005  # Gather Victim Network Information: IP Addresses
                 # Mapeamento de IP → MAC na rede local

  defense_evasion:
    - T1070      # Indicator Removal (restore())
                 # Limpeza das tabelas ARP após a captura
```

---

## `$ cat ./prerequisites.sh`

```bash
# Instalar dependências
pip install scapy

# Habilitar IP forwarding (OBRIGATÓRIO para MITM funcionar)
# Sem isso, os pacotes chegam ao atacante mas não são encaminhados
# → vítima perde conectividade com a internet

# Linux
echo 1 > /proc/sys/net/ipv4/ip_forward

# macOS
sysctl -w net.inet.ip.forwarding=1

# Verificar interface de rede disponível
ip link show        # Linux
ifconfig            # macOS
```

> **Por que IP forwarding é crítico?**
> Sem ele, o kernel do atacante descarta os pacotes destinados a outros IPs em vez de encaminhá-los. A vítima perde conexão com a internet — o que gera alertas imediatos e destrói o sigilo do ataque.

---

## `$ cat ./usage.sh`

```bash
# Sintaxe
sudo python arper.py [victim_ip] [gateway_ip] [interface]

# Exemplo
sudo python arper.py 192.168.1.50 192.168.1.1 eth0
```

```
# Output esperado:
eth0 inicializada
Gateway (192.168.1.1) está em aa:bb:cc:11:22:33
Vítima  (192.168.1.50) está em dd:ee:ff:44:55:66
------------------------------
IP de origem: 192.168.1.1
IP de destino: 192.168.1.50
MAC de destino: dd:ee:ff:44:55:66
...
Iniciando o envenenamento ARP. [CTRL-C para interromper]
..............................
Capturando 100 pacotes
Pacotes recebidos
Restaurando tabelas ARP....
Concluído
```

```bash
# Analisar o pcap capturado
wireshark arper.pcap
# ou
tshark -r arper.pcap -Y "http"        # filtrar apenas HTTP
tshark -r arper.pcap -Y "dns"         # filtrar apenas DNS
```

---

## `$ cat ./detection_opportunities.md`

> Como esse ataque é detectável pelo lado defensivo.

| Indicador | Método de Detecção |
|-----------|-------------------|
| ARP Replies sem Request anterior | IDS com inspeção ARP stateful (ex: ARPwatch, XArp) |
| Mesmo MAC anunciado para dois IPs diferentes | Tabela ARP do switch / SIEM correlacionando ARP logs |
| Gateway com MAC duplicado na rede | `arp -a` na vítima mostra MAC do atacante no lugar do gateway |
| Volume anormal de ARP Replies | Threshold alert em NetFlow / switch port security |
| Entrada ARP mudando repetidamente | Dynamic ARP Inspection (DAI) em switches gerenciados |

**Mitigação efetiva:**
- **Dynamic ARP Inspection (DAI)** em switches gerenciados — valida ARP contra DHCP snooping binding table
- **Static ARP entries** para gateway em hosts críticos
- **Segmentação de rede** — VLANs limitam o escopo do broadcast ARP

---

## `$ cat ./lessons_learned.txt`

```
[+] ARP é fundamentalmente não autenticado — o protocolo assume confiança na LAN
[+] Envenenamento bidirecional é obrigatório para MITM completo — apenas um lado = traffic black hole
[+] BPF filters no kernel são muito mais eficientes que filtragem no espaço do usuário
[+] multiprocessing resolve o GIL para tarefas paralelas de I/O intensivo com Scapy
[+] restore() é crítico — sem cleanup, a vítima perde conectividade e o ataque se torna óbvio
[-] Sem IP forwarding habilitado, o ataque causa DoS na vítima — conectividade cai
[-] ARP Replies em broadcast são detectáveis por ARPwatch e switches com DAI
[-] count=100 fixo no sniffer é inflexível — idealmente parametrizado via CLI
[-] gateway referenciado como variável global em sniff_packets() — melhor passado como argumento
```

---

<p align="center">
  <i>Built for lab environments · Includes ARP restore · MITRE ATT&CK T1557.002</i>
</p>
