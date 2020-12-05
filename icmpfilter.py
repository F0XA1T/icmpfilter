from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import socket
import subprocess
import re
import argparse

parse = argparse.ArgumentParser()
parse.add_argument("-i", "--iface", dest = "interface", type = str, help = "interface name, example: wlan0, eth0")
parse.add_argument("-q", "--queue-num", dest = "queuenum", type = int, help = "queue number, example: 0, 1, 2")
parse.add_argument("-x", "--xterm", action = "store_true", help = "run program in xterm terminal")
args = vars(parse.parse_args())

interface = args["interface"]
queuenum = args["queuenum"]
xterm = args["xterm"]

def getip(iface):
    ifconfig = subprocess.check_output("ifconfig " + iface, shell = True).decode()
    ifconfig_list = ifconfig.splitlines()
    ip = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ifconfig_list[1])[0]

    return ip

ip = getip(interface)

def icmpfilter(pack):
    scpack = IP(pack.get_payload())

    if scpack.haslayer(ICMP) and scpack[ICMP].type == 8 and scpack[IP].dst == ip:
        pack.drop()
        print(u"\u001b[33m[DROP]\u001b[0m ICMP PING FROM \u001b[37;1m{0}\u001b[0m DROPPED".format(scpack[IP].src))

    else:
        pack.set_payload(bytes(scpack))

        pack.accept()



def main():
    if xterm:
        os.system("xterm -e python3 {0} --iface {1} --queue-num {2}".format(sys.argv[0], interface, str(queuenum)))
        sys.exit()
    print(u"\u001b[33m[INFO]\u001b[0m RUNING ON \u001b[32;1m{0}\u001b[0m INTERFACE AND \u001b[32;1m{1}\u001b[0m QUEUE NUMBER\n".format(interface.upper(), str(queuenum)))
    os.system("iptables -I INPUT -j NFQUEUE --queue-num " + str(queuenum))

    queue = NetfilterQueue()

    try:
        queue.bind(queuenum, icmpfilter)
        queue.run()
    except:
        pass

    print(u"\n\u001b[33m[INFO]\u001b[0m \u001b[31;1mQUITING...\u001b[0m")
    os.system("iptables --flush")
    queue.unbind()
    sys.exit(3)


if __name__ == "__main__":
    main()
