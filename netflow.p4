  /* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4   = 0x800;
const bit<16> TYPE_IPV6   = 0x86dd;
const bit<16> TYPE_VLAN   = 0x8100;
const bit<8>  TYPE_TCP    = 6;
const bit<8>  TYPE_UDP    = 17;
const bit<8>  TYPE_ICMP   = 1;
const bit<8>  TYPE_ICMPV6 = 58;

#define AMOUNT_OF_FLOWS 8192


register<bit<32>>(1) flow_counter;
register<bit<32>>(AMOUNT_OF_FLOWS)  transmitted_packet_counter;
register<bit<32>>(AMOUNT_OF_FLOWS)  received_packet_counter;
register<bit<32>>(AMOUNT_OF_FLOWS)  transmitted_byte_counter;
register<bit<32>>(AMOUNT_OF_FLOWS)  received_byte_counter;
register<bit<32>>(AMOUNT_OF_FLOWS)  dstip_register;
register<bit<32>>(AMOUNT_OF_FLOWS)  srcip_register;
register<bit<16>>(AMOUNT_OF_FLOWS)  dstport_register;
register<bit<16>>(AMOUNT_OF_FLOWS)  srcport_register;
register<bit<8>>(AMOUNT_OF_FLOWS)   protocol_register;
/*
register<bit<8>>(AMOUNT_OF_FLOWS)   tcp_flag_register;
*/


register<bit<48>>(AMOUNT_OF_FLOWS)  src_to_dst_last_time_register;
register<bit<48>>(AMOUNT_OF_FLOWS)  dst_to_src_last_time_register;
register<bit<48>>(AMOUNT_OF_FLOWS)  src_to_dst_flow_duration_register;
register<bit<48>>(AMOUNT_OF_FLOWS)  dst_to_src_flow_duration_register;

register<bit<8>>(AMOUNT_OF_FLOWS)    max_ttl_register;
register<bit<8>>(AMOUNT_OF_FLOWS)    min_ttl_register;

register<bit<16>>(AMOUNT_OF_FLOWS)   max_ip_pkt_len_register; 
register<bit<16>>(AMOUNT_OF_FLOWS)   min_ip_pkt_len_register; 

register<bit<32>>(AMOUNT_OF_FLOWS)   num_of_ip_totalLen_up_to_128_bytes_register; 
register<bit<32>>(AMOUNT_OF_FLOWS)   num_of_ip_totalLen_128_to_256_bytes_register;
register<bit<32>>(AMOUNT_OF_FLOWS)   num_of_ip_totalLen_256_to_512_bytes_register; 
register<bit<32>>(AMOUNT_OF_FLOWS)   num_of_ip_totalLen_512_to_1024_bytes_register;
register<bit<32>>(AMOUNT_OF_FLOWS)   num_of_ip_totalLen_1024_to_1514_bytes_register;

register<bit<16>>(AMOUNT_OF_FLOWS)   max_tcp_win_src_to_dst_register;
register<bit<16>>(AMOUNT_OF_FLOWS)   max_tcp_win_dst_to_src_register;

register<bit<32>>(AMOUNT_OF_FLOWS)   bytes_per_second_src_to_dst_register; 
register<bit<32>>(AMOUNT_OF_FLOWS)   bytes_per_second_dst_to_src_register;

register<bit<32>>(AMOUNT_OF_FLOWS)   bits_per_second_src_to_dst_register; 
register<bit<32>>(AMOUNT_OF_FLOWS)   bits_per_second_dst_to_src_register;

//for test
register<bit<32>>(1) current_flow_id_reg;
register<bit<32>>(1) current_flow_r_id_reg;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header vlan_t {
    bit<3>    pcp;
    bit<1>    cfi;
    bit<12>   vid;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel; 
    bit<16>   payloadLen;
    bit<8>    protocol;
    bit<8>    hopLimit;
    bit<128>  srcAddr;
    bit<128>  dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header icmp_t {
    bit<16> type;
    bit<16> code;
    bit<16> hdrChecksum;
}

header icmpv6_t {
    bit<16> type;
    bit<16> code;
    bit<16> hdrChecksum;
}

struct metadata {
    bit<1> malicious;
    bit<32> port;
}

struct headers {
    ethernet_t   ethernet;
    vlan_t       vlan;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    tcp_t        tcp;
    udp_t        udp;
    icmp_t       icmp;
    icmpv6_t     icmpv6;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    /*****************start**********************/
    state start {
        transition parse_ethernet;
    }

    /*****************L2**********************/
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_VLAN: parse_vlan;
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    /*****************vlan**********************/
    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    /*****************L3**********************/
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            TYPE_ICMP: icmp;
            TYPE_ICMPV6: icmpv6;
            default: accept;
        }
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            TYPE_ICMP: icmp;
            TYPE_ICMPV6: icmpv6;
            default: accept;
        }
    }

    /*****************L4**********************/
    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
    state udp {
       packet.extract(hdr.udp);
       transition accept;
    }
    state icmp {
       packet.extract(hdr.icmp);
       transition accept;
    }
    state icmpv6 {
       packet.extract(hdr.icmpv6);
       transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
                    
    //construct a counter all_packets
    counter(1,CounterType.packets_and_bytes) all_packets_bytes_counter;

    bit<32> flow_id;
    bit<32> suspected_target_id;
    bit<4>  packets_asymmetry_value;
    bit<32> quotient_integer=0;
    bit<32> quotientdecimal=0;

    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action compute_hashes_flow(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2)  {
       
       hash(flow_id, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,ipAddr2,port1,port2,hdr.ipv4.protocol},(bit<32>)AMOUNT_OF_FLOWS);
    }

    action calculate_division_precise(bit<32> numerator, bit<32> denominator){
      
        bit<32> tmp_difference=0;
        bit<32> tmp_difference_double=0;
        bit<32> numerator_double=0;
        if (numerator < denominator){// asymmetry less than 1 by division
            quotient_integer = 0;
            numerator_double = numerator *2;
            if (numerator_double > denominator){//the decimal part should be nearly 0.75, because denominator/2 <= tmp_difference < denominator
                quotientdecimal = 75;
            }else if (numerator_double == denominator){//the decimal part should be nearly 0.25, because  0 <= tmp_difference < denominator/2
                quotientdecimal = 50;
            }else{
                quotientdecimal = 25;
            }
        }else if (numerator == denominator){
            quotient_integer = 0;
            quotientdecimal = 0;
        }else{//the integer part of the division result is bigger than 0
            quotient_integer = 1;
            tmp_difference = numerator - denominator;
            if (tmp_difference < denominator){
                //calculate decimal part
                if (tmp_difference==0){
                    quotientdecimal = 0;
                }else{
                    tmp_difference_double = tmp_difference * 2;
                    if (tmp_difference_double > denominator){//the decimal part should be nearly 0.75, because denominator/2 <= tmp_difference < denominator
                        quotientdecimal = 75;
                    }else if (tmp_difference_double == denominator){//the decimal part should be nearly 0.25, because  0 <= tmp_difference < denominator/2
                        quotientdecimal = 50;
                    }else{
                        quotientdecimal = 25;
                    }
                }
            }else{//the integer part of the division result is bigger than 1 //8=8
                quotient_integer = 2;
                tmp_difference = tmp_difference - denominator; //8-8=0
                if (tmp_difference < denominator){
                    //calculate decimal part
                    if (tmp_difference==0){
                        quotientdecimal = 0;
                    }else{
                        tmp_difference_double = tmp_difference * 2;
                        if (tmp_difference_double > denominator){//the decimal part should be nearly 0.75, because denominator/2 <= tmp_difference < denominator
                            quotientdecimal = 75;
                        }else if (tmp_difference_double == denominator){//the decimal part should be nearly 0.25, because  0 <= tmp_difference < denominator/2
                            quotientdecimal = 50;
                        }else{
                            quotientdecimal = 25;
                        }
                    }
                }else{//the integer part of the division result is bigger than 2 
                    quotient_integer = 3;
                    tmp_difference = tmp_difference - denominator;
                    if (tmp_difference < denominator){
                        //calculate decimal part
                        if (tmp_difference==0){
                            quotientdecimal = 0;
                        }else{
                            tmp_difference_double = tmp_difference * 2;
                            if (tmp_difference_double > denominator){//the decimal part should be nearly 0.75, because denominator/2 <= tmp_difference < denominator
                                quotientdecimal = 75;
                            }else if (tmp_difference_double == denominator){//the decimal part should be nearly 0.25, because  0 <= tmp_difference < denominator/2
                                quotientdecimal = 50;
                            }else{
                                quotientdecimal = 25;
                            }
                        }
                    }else{//the integer part of the division result is bigger than 3
                        quotient_integer = 4;
                        tmp_difference = tmp_difference - denominator;
                        if (tmp_difference < denominator){
                            //calculate decimal part
                            if (tmp_difference==0){
                                quotientdecimal = 0;
                            }else{
                                tmp_difference_double = tmp_difference * 2;
                                if (tmp_difference_double > denominator){//the decimal part should be nearly 0.75, because denominator/2 <= tmp_difference < denominator
                                    quotientdecimal = 75;
                                }else if (tmp_difference_double == denominator){//the decimal part should be nearly 0.25, because  0 <= tmp_difference < denominator/2
                                    quotientdecimal = 50;
                                }else{
                                    quotientdecimal = 25;
                                }
                            }
                        }else{//the integer part of the division result is bigger than 4
                            quotient_integer = 5;
                            tmp_difference = tmp_difference - denominator;
                            if (tmp_difference < denominator){
                                //calculate decimal part
                                if (tmp_difference==0){
                                    quotientdecimal = 0;
                                }else{
                                    tmp_difference_double = tmp_difference * 2;
                                    if (tmp_difference_double > denominator){//the decimal part should be nearly 0.75, because denominator/2 <= tmp_difference < denominator
                                       quotientdecimal = 75;
                                    }else if (tmp_difference_double == denominator){//the decimal part should be nearly 0.25, because  0 <= tmp_difference < denominator/2
                                        quotientdecimal = 50;
                                    }else{
                                        quotientdecimal = 25;
                                    }
                                }
                            }else{//the integer part of the division result is bigger than 5
                                quotient_integer = 6;
                                tmp_difference = tmp_difference - denominator;
                                if (tmp_difference < denominator){
                                    //calculate decimal part
                                    if (tmp_difference==0){
                                       quotientdecimal = 0;
                                    }else{
                                        tmp_difference_double = tmp_difference * 2;
                                        if (tmp_difference_double > denominator){//the decimal part should be nearly 0.75, because denominator/2 <= tmp_difference < denominator
                                            quotientdecimal = 75;
                                        }else if (tmp_difference_double == denominator){//the decimal part should be nearly 0.25, because  0 <= tmp_difference < denominator/2
                                            quotientdecimal = 50;
                                        }else{
                                            quotientdecimal = 25;
                                        }
                                    }
                                }else{//the integer part of the division result is bigger than 6
                                    quotient_integer = 7;
                                    quotientdecimal = 0;
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    table port_foward {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }


    apply {
        if (hdr.ipv4.isValid()){
                all_packets_bytes_counter.count(0);
                bit<1>  is_malicious=0;
                bit<16> tmpsrcPort=0;
                bit<16> tmpdstPort=0;

                /**********************************NetFlow Function*****************************/
                if (hdr.tcp.isValid() || hdr.udp.isValid()){

                    //get srcport and dstport
                    if (hdr.tcp.isValid()){
                    tmpdstPort = hdr.tcp.dstPort;
                    tmpsrcPort = hdr.tcp.srcPort;
                    }else{
                    tmpdstPort = hdr.udp.dstPort;
                    tmpsrcPort = hdr.udp.srcPort;
                    }
                }
                    bit<32> current_flow_id=0;
                    bit<32> current_flow_r_id=0;


                    //Get register position, namely Flow id, and name it as current_flow_id
                    compute_hashes_flow(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, tmpdstPort, tmpsrcPort);
                    current_flow_id = flow_id;
                    current_flow_id_reg.write(0,flow_id);
                    
                    //change the ipaddrs and ports and get the current_flow_r_id of the reverse direction flow
                    compute_hashes_flow(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, tmpsrcPort, tmpdstPort);
                    current_flow_r_id = flow_id;
                    current_flow_r_id_reg.write(0,flow_id);

                    /***********************for normal direction**********************/
                    
                    bit<32> A_current_flow_transmitted_packet=0;
                    bit<32> A_current_flow_transmitted_byte=0;
                     transmitted_packet_counter.read(A_current_flow_transmitted_packet,current_flow_id);
                     transmitted_byte_counter.read(A_current_flow_transmitted_byte,current_flow_id);
                    if (A_current_flow_transmitted_packet==0){
                        // if the flow is new, record the new flow's 5-tuple
                         dstip_register.write((bit<32>)current_flow_id,hdr.ipv4.dstAddr);
                         srcip_register.write((bit<32>)current_flow_id,hdr.ipv4.srcAddr);
                         dstport_register.write((bit<32>)current_flow_id,tmpdstPort);
                         srcport_register.write((bit<32>)current_flow_id,tmpsrcPort);
                         protocol_register.write((bit<32>)current_flow_id,hdr.ipv4.protocol);

                        //refresh the packet amount according to the current_flow_id
                         transmitted_packet_counter.write(current_flow_id,(A_current_flow_transmitted_packet+1));
                        //refresh the byte amount according to the current_flow_id
                         transmitted_byte_counter.write(current_flow_id,(A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen)));
                    }else{
                        // if the flow has been recorded
                        //refresh the packet amount according to the current_flow_id
                         transmitted_packet_counter.write(current_flow_id,(A_current_flow_transmitted_packet+1));
                        //refresh the byte amount according to the current_flow_id
                         transmitted_byte_counter.write(current_flow_id,(A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen)));
                    }
                    // accumulate current timestamp
                    bit<48> flow_hold_time;
                    src_to_dst_flow_duration_register.read(flow_hold_time,current_flow_id);
                    flow_hold_time = flow_hold_time + standard_metadata.ingress_global_timestamp;
                    src_to_dst_flow_duration_register.write(current_flow_id,flow_hold_time);
                    // bytes_per_second

                    // record the current timestamp
                    src_to_dst_last_time_register.write(current_flow_id,standard_metadata.ingress_global_timestamp);
                 

                    ///////for reverse direction
                    bit<32> A_current_flow_r_received_packet;
                    bit<32> A_current_flow_r_received_byte;
                     received_packet_counter.read(A_current_flow_r_received_packet,current_flow_r_id);
                     received_byte_counter.read(A_current_flow_r_received_byte,current_flow_r_id);
                    if (A_current_flow_r_received_packet==0){
                        // if the flow is new, record the new flow's 5-tuple
                         dstip_register.write((bit<32>)current_flow_r_id,hdr.ipv4.srcAddr);
                         srcip_register.write((bit<32>)current_flow_r_id,hdr.ipv4.dstAddr);
                         dstport_register.write((bit<32>)current_flow_r_id,tmpsrcPort);
                         srcport_register.write((bit<32>)current_flow_r_id,tmpdstPort);
                         protocol_register.write((bit<32>)current_flow_r_id,hdr.ipv4.protocol);
                        
                        //refresh the packet amount according to the current_flow_id
                         received_packet_counter.write(current_flow_r_id,(A_current_flow_r_received_packet+1));
                        //refresh the byte amount according to the current_flow_id
                         received_byte_counter.write(current_flow_r_id,(A_current_flow_r_received_byte + ((bit<32>)hdr.ipv4.totalLen)));
                    }else{
                        // if the flow has been recorded
                        //refresh the packet amount according to the current_flow_id
                         received_packet_counter.write(current_flow_r_id,(A_current_flow_r_received_packet+1));
                        //refresh the byte amount according to the current_flow_id
                         received_byte_counter.write(current_flow_r_id,(A_current_flow_r_received_byte + ((bit<32>)hdr.ipv4.totalLen)));
                    }
                    // accumulate current timestamp
                    bit<48> reverse_flow_hold_time;
                    dst_to_src_flow_duration_register.read(reverse_flow_hold_time,current_flow_r_id);
                    reverse_flow_hold_time = reverse_flow_hold_time + standard_metadata.ingress_global_timestamp;
                    dst_to_src_flow_duration_register.write(current_flow_r_id,reverse_flow_hold_time);
                    // bytes_per_second

                    // record the current timestamp
                    dst_to_src_last_time_register.write(current_flow_r_id,standard_metadata.ingress_global_timestamp);

                    //////fields for Decision Tree
                    //timestamp

                    ///max tll min ttl
                    bit<8>   recorded_max_ttl;
                    bit<8>   recorded_min_ttl;
                     max_ttl_register.read( recorded_max_ttl,current_flow_id);
                     max_ttl_register.read( recorded_min_ttl,current_flow_id);

                    if (hdr.ipv4.ttl >  recorded_max_ttl){
                        //refresh max ttl
                         max_ttl_register.write(current_flow_id,hdr.ipv4.ttl);
                    }else{
                        //no action, just keep the recorded max ttl
                    }

                    if (hdr.ipv4.ttl <  recorded_min_ttl){
                        //refresh min ttl
                         min_ttl_register.write(current_flow_id,hdr.ipv4.ttl);
                    }else{
                        //no action, just keep the recorded min ttl
                    }

                    ///max ip_pkt_len  min ip_pkt_len
                    bit<16>   recorded_max_ip_pkt_len;
                    bit<16>   recorded_min_ip_pkt_len;
                     max_ip_pkt_len_register.read( recorded_max_ip_pkt_len,current_flow_id);
                     min_ip_pkt_len_register.read( recorded_min_ip_pkt_len,current_flow_id);

                    if (hdr.ipv4.totalLen >  recorded_max_ip_pkt_len){
                        //refresh max ip_pkt_len
                         max_ip_pkt_len_register.write(current_flow_id,hdr.ipv4.totalLen);
                    }else{
                        //no action, just keep the recorded max ip_pkt_len
                    }

                    if (hdr.ipv4.totalLen <  recorded_min_ip_pkt_len){
                        //refresh min ip_pkt_len
                         min_ip_pkt_len_register.write(current_flow_id,hdr.ipv4.totalLen);
                    }else{
                        //no action, just keep the recorded min ip_pkt_len
                    }

                    /// num_of_ip_totalLen
                    if ((1024 < hdr.ipv4.totalLen) && (hdr.ipv4.totalLen <= 1514)){
                        //accumulate  num_of_ip_totalLen_up_to_128_bytes_register
                        bit<32>  num_of_ip_totalLen_1024_to_1514_bytes;
                         num_of_ip_totalLen_1024_to_1514_bytes_register.read( num_of_ip_totalLen_1024_to_1514_bytes,current_flow_id);
                         num_of_ip_totalLen_1024_to_1514_bytes_register.write(current_flow_id, num_of_ip_totalLen_1024_to_1514_bytes+1);
                    }else if ((512 < hdr.ipv4.totalLen)&&(hdr.ipv4.totalLen<= 1024)){
                        // accumulate  num_of_ip_totalLen_512_to_1024_bytes_register
                        bit<32>  num_of_ip_totalLen_512_to_1024_bytes;
                         num_of_ip_totalLen_512_to_1024_bytes_register.read( num_of_ip_totalLen_512_to_1024_bytes,current_flow_id);
                         num_of_ip_totalLen_512_to_1024_bytes_register.write(current_flow_id, num_of_ip_totalLen_512_to_1024_bytes+1);
                    }else if((256 < hdr.ipv4.totalLen)&&(hdr.ipv4.totalLen <= 512)){
                        // accumulate  num_of_ip_totalLen_256_to_512_bytes_register
                        bit<32>  num_of_ip_totalLen_256_to_512_bytes;
                         num_of_ip_totalLen_256_to_512_bytes_register.read( num_of_ip_totalLen_256_to_512_bytes,current_flow_id);
                         num_of_ip_totalLen_256_to_512_bytes_register.write(current_flow_id, num_of_ip_totalLen_256_to_512_bytes+1);
                    }else if((128 < hdr.ipv4.totalLen)&&(hdr.ipv4.totalLen <= 256)){
                        // accumulate  num_of_ip_totalLen_128_to_256_bytes_register
                         bit<32>  num_of_ip_totalLen_128_to_256_bytes;
                         num_of_ip_totalLen_128_to_256_bytes_register.read( num_of_ip_totalLen_128_to_256_bytes,current_flow_id);
                         num_of_ip_totalLen_128_to_256_bytes_register.write(current_flow_id, num_of_ip_totalLen_128_to_256_bytes+1);
                    }else if(hdr.ipv4.totalLen <= 128){
                       //accumulate  num_of_ip_totalLen_up_to_128_bytes_register
                        bit<32>  num_of_ip_totalLen_up_to_128_bytes;
                         num_of_ip_totalLen_up_to_128_bytes_register.read( num_of_ip_totalLen_up_to_128_bytes,current_flow_id);
                         num_of_ip_totalLen_up_to_128_bytes_register.write(current_flow_id, num_of_ip_totalLen_up_to_128_bytes+1);
                    }else{
                        // no action
                    }

                    ///max_tcp_win
                    if (hdr.tcp.isValid()){
                        //src_to_dst
                        bit<16>  recorded_max_tcp_win_src_to_dst;
                         max_tcp_win_src_to_dst_register.read( recorded_max_tcp_win_src_to_dst,current_flow_id);
                        if (hdr.tcp.window >  recorded_max_tcp_win_src_to_dst){
                             max_tcp_win_src_to_dst_register.write(current_flow_id, hdr.tcp.window);
                        }else{
                            // no action
                        }
                        //dst_to_src
                        bit<16>  recorded_max_tcp_win_dst_to_src;
                         max_tcp_win_dst_to_src_register.read( recorded_max_tcp_win_dst_to_src,current_flow_r_id);
                        if (hdr.tcp.window >  recorded_max_tcp_win_dst_to_src){
                             max_tcp_win_dst_to_src_register.write(current_flow_r_id, hdr.tcp.window);
                        }else{
                            // no action
                        }
                    }else{
                        // no action
                    }

                

            
            //basic forwarding
            port_foward.apply();
        }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {



    apply {}
    
}
     
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply { 
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

     }
            
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
     
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
