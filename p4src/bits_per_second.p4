   /* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
action bits_per_second_calculation(in bit<48> num_of_2_microseconds, in bit<48> transmitted_byte, out bit<48> bits_per_second){
    if ( num_of_2_microseconds == 3 ){
        // src_to_dst_bytes_speed << 3, namely (transmitted_byte >> 3) << 3
        bits_per_second = transmitted_byte;
        }else if (num_of_2_microseconds > 3){
        // src_to_dst_bytes_speed << 3, namely (transmitted_byte>> 10) << 3
        bits_per_second = transmitted_byte >> (num_of_2_microseconds - 3);
        }else{
        // src_to_dst_bytes_speed << 3, namely (transmitted_byte >> 3) << 3
        bits_per_second = transmitted_byte << ( 3 - num_of_2_microseconds);
        }
}
      