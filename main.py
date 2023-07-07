from scapy.layers.tls.cert import PrivKey
from scapy.layers.tls.session import *
from scapy.all import *

# find best game
if __name__ == '__main__':
	
    load_layer("tls")
    pcapFile = "/home/burakkutlu/task3/best_game.pcap"
    privateKey = "/home/burakkutlu/task3/server.key"
    keystr = open(privateKey, 'rb').read()
    packets = rdpcap(pcapFile)

    privKeyObject = PrivKey(privateKey)

    res = sniff(offline=packets, session=TLSSession(server_rsa_key=privKeyObject))

    for index, s in enumerate(res):
        if s.haslayer('TLS'):
            print s.show()


