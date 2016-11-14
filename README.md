# DNS_Spoofer

## What is Arp Spoofing?
ARP spoofing or ARP cache poisoning is a technique by which an attacker sends spoofed ARP packets onto a LAN. Basically the attacker machine fools the gateway and the victim machine into exchanging network packets via the attacker machine. This allows the attacker machine to intercept network packets that are travelling between the gateway and the victim machine.
## What is DNS Spoofing?
DNS spoofing, also referred to as DNS cache poisoning in which spoofed Domain Name System data is injected into a DNS resolvers cache, causing the name server to return an incorrect IP address or the IP address you as an attacker chose. Once the victim is DNS spoofed any DNS request coming from the victim machine the website that the attacker specified will be redirected to a malicious website.
## What’s the use of this program?
This program is used to first ARP poison the victim machine in order to get the traffic flow via attacker. And then using DNS spoof redirect to a malicious website.


## 2. Flags

Our program use the following flags in order to successfully DNS spoof a victim machine.
- **-h, --help:**Used to display the usage information
- **-i, --interface:**Local interface of the network card IP address to Spoof
- **-d, --destination:**IP address to Spoof 
- **-r, --router:**IP address of the gateway/router
- **-w, --webiste:**To Spoof (Can you multiple websites) To redirect to
- **-n, --new_website**: The webiste to redirect
- **-t, --title:**Process name

## Command
`python mitm.py -i wlp2s0 -d 192.168.0.12 -r 192.168.0.1 -w codeshare.io,monkey.com,tiger.com -n milliways.bcit.ca -t hidden`



