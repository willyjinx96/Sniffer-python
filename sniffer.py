#Packet sniffer in python

import socket, sys
import struct

# Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
	s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except: 
	print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(65565)
	
	#packet string from tuple
    packet = packet[0]  
	
	#parse ethernet header
    eth_length = 14
	
    eth_header = packet[:eth_length]
    eth = struct.unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    
    print("\n\n\t<<<<<<<       DATOS PERSONALES       >>>>>>>")
    print("\t< Nombre: Williams Fernando Quispe Condori >")
    print("\t< CI    : 10001379 LP                      >")
    print("\nEthernet Header")
    print("\t|-Destination MAC \t: " + get_mac_addr(eth[0]))
    print("\t|-Source MAC \t\t: " + get_mac_addr(eth[1]))
    print("\t|-Protocol \t\t: " + str(eth_protocol))

#Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        ip_header = packet[eth_length:20+eth_length]
        #now unpack them :)
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4


        ip_tos = iph[1] # char
        ip_len = iph[2] # short int
        ip_id = iph[3]  # short int
        ip_off = iph[4] # short int
        #------------------
        ip_ttl = iph[5] #char
        protocol = iph[6]
        ip_sum = iph[7] #shor int

        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        print("\nIP Header")
        print('\t|-IP Version\t\t :  ' + str(version) )
        print('\t|-IP Header Length (IHL) : ' ,ihl, 'DWORDS or',str(ihl*32//8) ,'bytes')
        print('\t|-Type of Service (TOS)\t : ',str(ip_tos))
        print('\t|-IP Total Length\t : ',ip_len, ' DWORDS ',str(ip_len*32//8) ,'bytes')
        print('\t|-Identification\t : ',ip_id)        
        print('\t|-TTL\t\t\t :  ' + str(ip_ttl))
        print('\t|-Protocol\t\t :  ' + str(protocol))
        print('\t|-Cheksum\t\t : ', ip_sum)
        print('\t|-Source IP\t\t :  ' + str(s_addr) )
        print('\t|-Destination IP\t :  ' + str(d_addr))


		#TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

			#now unpack them :)
            tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
			
            source_port = tcph[0]   # uint16_t
            dest_port = tcph[1]     # uint16_t
            sequence = tcph[2]      # uint32_t
            acknowledgement = tcph[3]   # uint32_t
            doff_reserved = tcph[4]     # uint8_t
            tcph_length = doff_reserved >> 4
            tcph_flags = tcph[5]            #uint8_t
            tcph_window_size = tcph[6]      #uint16_t
            tcph_checksum = tcph[7]         #uint16_t
            tcph_urgent_pointer = tcph[8]   #uint16_t
            
            print("\nTCP Header")
            
            print("\t|-Source Port\t\t : ",source_port)
            print("\t|-Destination Port\t : ",dest_port)
            print("\t|-Sequence Number\t : ",sequence)
            print("\t|-Acknowledge Number\t : ",acknowledgement)
            print("\t|-Header Length\t\t : ",tcph_length,'DWORDS or ',str(tcph_length*32//8) ,'bytes')

            #print("\t|-Congestion Window Reduced Flag (CWR)\t : ", '1 ' if(tcph_flags & 128 == 128) else '0 ')
            #print("\t|-ECN - Echo Flag (ECE)\t\t\t : ", '1 ' if(tcph_flags & 64 == 64) else '0 ')
            print("\t|-Urgent Flag (URG)\t\t\t : ", '1 ' if(tcph_flags & 32 == 32) else '0 ')
            print("\t|-Acknowledgement Flag (ACK)\t\t : ", '1 ' if(tcph_flags & 316 == 16) else '0 ')
            print("\t|-Push Flag (PSH)\t\t\t : ", '1 ' if(tcph_flags & 8 == 8) else '0 ')
            print("\t|-Reset Flag (RST)\t\t\t : ", '1 ' if(tcph_flags & 4 == 4) else '0 ')
            print("\t|-Synchronise Flag (SYN)\t\t : ", '1 ' if(tcph_flags & 2 == 2) else '0 ')
            print("\t|-Finish Flag (FIN)\t\t\t : ", '1 ' if(tcph_flags & 1 == 1) else '0 ')

            print("\t|-Window Size\t\t : ",tcph_window_size)
            print("\t|-Checksum\t\t : ",tcph_checksum)
            print("\t|-Urgent Pointer\t : ",tcph_urgent_pointer)

		#ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

			#now unpack them :)
            icmph = struct.unpack('!BBH' , icmp_header)
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            print('\nICMP Header')
            print('\t|-Type\t\t\t : ' + str(icmp_type))
            print('\t|-Code\t\t\t : ' + str(code))
            print('\t|-Checksum\t\t : ' + str(checksum))

		#UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

			#now unpack them :)
            udph = struct.unpack('!HHHH' , udp_header)
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            print('\nUDP Header')
            print('\t|-Source Port\t : ' + str(source_port))
            print('\t|-Dest Port\t : ' + str(dest_port))
            print('\t|-Length\t : ' + str(length))
            print('\t|-Checksum\t : ' + str(checksum))
			
		#some other IP packet like IGMP
        else :
            print ('Protocol other than TCP/UDP/ICMP')
			