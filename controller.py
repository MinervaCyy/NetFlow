from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
import sys
import math
import socket
import struct
import math
import pandas as pd

class ReadRegisters(object):

    def __init__(self, sw_name):

        self.topo = Topology(db="topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
    
    def hex_to_ipaddr(self,hex_addr):

       #addr_long = int(s, 16)
       #print(hex(addr_long))  # '0x200a8c0'
       #print(struct.pack("<L", addr_long))  # '\xc0\xa8\x00\x02'
       ip_addr=socket.inet_ntoa(struct.pack("<L", hex_addr))
       # Split IP address into octets
       octets = ip_addr.split('.')
       # Convert octets to integers
       octets = [int(octet) for octet in octets]
       # Transfer the octets
       new_octets = [octets[3], octets[2], octets[1], octets[0]]
       # Join the octets back into an IP address string
       new_ip = '.'.join(map(str, new_octets))
       return new_ip  # '192.168.0.2'
    
    def cal_expected_asymmetry(self, trans, receive):
        if trans==receive:
            asymmetry=0
        else:
            asymmetry = (trans+1)/float((receive+1))
        return asymmetry

    def outcsv(self):

       txt_file = 'output.txt'
       df = pd.read_csv(txt_file, delimiter=',')

    
       csv_file = 'output.csv'
       df.to_csv(csv_file, index=False,header=True)

     

    def read(self):

        with open('output.txt', 'w') as f:
            
            f.write("index,"+"transmitted_packet,"+"received_packet,"+"transmitted_byte,"+"received_byte,"+"dstip,"+"srcip,"+"dstport,"+"srcport,"+"protocol,"+"src_to_dst_flow_duration,"+"dst_to_src_flow_duration,"+"max_ttl,"+"min_ttl,"+"max_ip_pkt_len,"+"min_ip_pkt_len,"+"num_of_ip_totalLen_up_to_128_bytes,"+"num_of_ip_totalLen_128_to_256_bytes,"+"num_of_ip_totalLen_256_to_512_bytes,"+"num_of_ip_totalLen_512_to_1024_bytes,"+"num_of_ip_totalLen_1024_to_1514_bytes,"+"max_tcp_win_src_to_dst,"+"max_tcp_win_dst_to_src"+"\n")
                
            for i in range(0,8192):
            
                transmitted_packet       = self.controller.register_read("transmitted_packet_counter", i)
                received_packet          = self.controller.register_read("received_packet_counter", i)
                transmitted_byte         = self.controller.register_read("transmitted_byte_counter", i)
                received_byte            = self.controller.register_read("received_byte_counter", i)
                dstip                    = self.controller.register_read("dstip_register", i)
                srcip                    = self.controller.register_read("srcip_register", i)
                dstport                  = self.controller.register_read("dstport_register", i)
                srcport                  = self.controller.register_read("srcport_register", i)
                protocol                 = self.controller.register_read("protocol_register", i)
                src_to_dst_flow_duration = self.controller.register_read("src_to_dst_flow_duration_register", i)
                dst_to_src_flow_duration = self.controller.register_read("dst_to_src_flow_duration_register", i)
                max_ttl                  = self.controller.register_read("max_ttl_register", i)
                min_ttl                  = self.controller.register_read("min_ttl_register", i)
                max_ip_pkt_len           = self.controller.register_read("max_ip_pkt_len_register", i)
                min_ip_pkt_len           = self.controller.register_read("min_ip_pkt_len_register", i)
                num_of_ip_totalLen_up_to_128_bytes = self.controller.register_read("num_of_ip_totalLen_up_to_128_bytes_register", i)
                num_of_ip_totalLen_128_to_256_bytes = self.controller.register_read("num_of_ip_totalLen_128_to_256_bytes_register", i)
                num_of_ip_totalLen_256_to_512_bytes = self.controller.register_read("num_of_ip_totalLen_256_to_512_bytes_register", i)
                num_of_ip_totalLen_512_to_1024_bytes = self.controller.register_read("num_of_ip_totalLen_512_to_1024_bytes_register", i)
                num_of_ip_totalLen_1024_to_1514_bytes = self.controller.register_read("num_of_ip_totalLen_1024_to_1514_bytes_register", i)
                max_tcp_win_src_to_dst = self.controller.register_read("max_tcp_win_src_to_dst_register", i)
                max_tcp_win_dst_to_src = self.controller.register_read("max_tcp_win_dst_to_src_register", i)
               
                '''
                if (transmitted_packet>0) :
                    print("index: ",i,"  transmitted_packet: ",transmitted_packet,"  received_packet: ",received_packet,"  transmitted_byte: ",transmitted_byte," received_byte: ",received_byte," dstip: ",self.hex_to_ipaddr(dstip)," srcip: ",self.hex_to_ipaddr(srcip)," dstport: ",dstport," srcport: ",    srcport," packet asymmetry: ",precise_packetasymmetry_int,precise_packetasymmetry_dec)
                '''

                if ((transmitted_packet>0) | (received_packet>0)) :
                  f.write(str(i)+","+ str(transmitted_packet) +","+str(received_packet)+","+str(transmitted_byte)+","+str(received_byte)+","+ self.hex_to_ipaddr(dstip)+","+self.hex_to_ipaddr(srcip)+","+str(dstport)+","+str(srcport)+","+str(protocol) +","+str(src_to_dst_flow_duration) + ","+ str(dst_to_src_flow_duration)+","+str(max_ttl)+","+str(min_ttl)+","+str(max_ip_pkt_len)+","+str(min_ip_pkt_len)+","+str(num_of_ip_totalLen_up_to_128_bytes)+","+str(num_of_ip_totalLen_128_to_256_bytes)+","+str(num_of_ip_totalLen_256_to_512_bytes)+","+str(num_of_ip_totalLen_512_to_1024_bytes)+","+str(num_of_ip_totalLen_1024_to_1514_bytes)+","+str(max_tcp_win_src_to_dst)+","+str(max_tcp_win_dst_to_src)+"\n")
                #f.write(str(i)+","+ str(transmitted_packet) +","+str(received_packet)+","+str(transmitted_byte)+","+str(received_byte)+","+ self.hex_to_ipaddr(dstip)+","+self.hex_to_ipaddr(srcip)+","+str(dstport)+","+str(srcport)+","+str(ln_packetasymmetry_flag)+","+str(ln_packetasymmetry)+","+str(real_ln_asymmetry)+","+str(expected_ln_asymmetry)+","+str(error_ln_asymmetry)+","+str(precise_packetasymmetry_int) +","+str(precise_packetasymmetry_dec) + ","+ str(real_precise_asymmetry)+","+str(expected_precise_asymmetry)+","+str(error_precise_asymmetry)+"\n")
             
            #f.write("----------------------------------" + "\n")
            #all_packets_bytes_counter = self.controller.counter_read('all_packets_bytes_counter', 0)
            #f.write(str(all_packets_bytes_counter))
           
            #f.write("total packets:"+ str(all_packets_bytes_counter.packets)+"  total bytes:"+str(all_packets_bytes_counter.bytes)+"  total flows:"+ str(flow_counter))
            





if __name__ == "__main__":
    ReadRegisters("s1").read()
    ReadRegisters("s1").outcsv()