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
       // dst_to_src_bytes_per_second
                    bit<32> processed_received_byte;
                    processed_received_byte_counter.read(processed_received_byte,current_flow_r_id);
                    bit<48> processed_dst_to_src_last_time;
                    dst_to_src_last_calculated_time_register.read(processed_dst_to_src_last_time,current_flow_r_id);
                    if (reverse_flow_hold_time - processed_dst_to_src_last_time > 2000000 ){
                        // if time difference over 2 microseconds, update the bytes_per_second_dst_to_src_register by dividing bytes by 2 microseconds
                        bit<32> need_calculated_received_bytes = A_current_flow_r_received_byte + (bit<32>)hdr.ipv4.totalLen - processed_received_byte;
                        bit<32> dst_to_src_bytes_speed = need_calculated_received_bytes >> 1;
                        bytes_per_second_dst_to_src_register.write(current_flow_r_id,dst_to_src_bytes_speed);
                        processed_received_byte_counter.write(current_flow_r_id,(A_current_flow_r_received_byte + (bit<32>)hdr.ipv4.totalLen));
                        dst_to_src_last_calculated_time_register.write(current_flow_r_id,reverse_flow_hold_time);
                    }   
                    /*
                    // dst_to_src_bytes_per_second
                    bit<48> dst_to_src_num_of_2_microseconds;
                    dst_to_src_num_of_2_microseconds_register.read(dst_to_src_num_of_2_microseconds,current_flow_id);
                    if (flow_hold_time > (2000000 + dst_to_src_num_of_2_microseconds * 2000000)){
                        // if time difference over 2 microseconds, update the bytes_per_second_dst_to_src_register by dividing bytes by 2 microseconds
                        dst_to_src_num_of_2_microseconds = dst_to_src_num_of_2_microseconds + 1;
                       // bit<48> dst_to_src_bytes_speed = (bit<48>)(A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000 >> dst_to_src_num_of_2_microseconds;
                        //bytes_per_second_dst_to_src_register.write(current_flow_id,dst_to_src_bytes_speed);
                        dst_to_src_num_of_2_microseconds_register.write(current_flow_id,dst_to_src_num_of_2_microseconds);
                    }
                    /*
                    // dst_to_src_bits_per_second
                    bit<48> dst_to_src_bits_per_second;
                    bits_per_second_calculation (dst_to_src_num_of_2_microseconds,(bit<48>)((A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000), dst_to_src_bits_per_second);
                    bits_per_second_dst_to_src_register.write(current_flow_id,dst_to_src_bits_per_second);
                    */

                    // src_to_dst_bytes_per_second
                    //bit<48> src_to_dst_num_of_2_microseconds;
                    //src_to_dst_num_of_2_microseconds_register.read(src_to_dst_num_of_2_microseconds,current_flow_id);
                    bit<32> processed_transmitted_byte;
                    processed_transmitted_byte_counter.read(processed_transmitted_byte,current_flow_id);
                    bit<48> processed_src_to_dst_last_time;
                    src_to_dst_last_calculated_time_register.read(processed_src_to_dst_last_time,current_flow_id);
                    if (flow_hold_time - processed_src_to_dst_last_time > 2000000 ){
                        // if time difference over 2 microseconds, update the bytes_per_second_src_to_dst_register by dividing bytes by 2 microseconds
                        bit<32> need_calculated_transmitted_bytes = A_current_flow_transmitted_byte + (bit<32>)hdr.ipv4.totalLen - processed_transmitted_byte;
                        bit<32> src_to_dst_bytes_speed = need_calculated_transmitted_bytes >> 1;
                        bytes_per_second_src_to_dst_register.write(current_flow_id,src_to_dst_bytes_speed);
                        processed_transmitted_byte_counter.write(current_flow_id,(A_current_flow_transmitted_byte + (bit<32>)hdr.ipv4.totalLen));
                        src_to_dst_last_calculated_time_register.write(current_flow_id,flow_hold_time);
                    }
                    /*
                    // src_to_dst_bits_per_second
                    bit<48> src_to_dst_bits_per_second;
                    bits_per_second_calculation (src_to_dst_num_of_2_microseconds,(bit<48>)((A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000), src_to_dst_bits_per_second);
                    bits_per_second_src_to_dst_register.write(current_flow_id,src_to_dst_bits_per_second);
                    */
                    /*if ( src_to_dst_num_of_2_microseconds == 8 ){
                        // src_to_dst_bytes_speed << 8, namely (A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000 >> 8) << 8
                        bits_per_second_src_to_dst_register.write(current_flow_id,(A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000 );
                    }else if (src_to_dst_num_of_2_microseconds > 8){
                        // src_to_dst_bytes_speed << 8, namely (A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000 >> 10) << 8
                        bits_per_second_src_to_dst_register.write(current_flow_id,(A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000 >> (src_to_dst_num_of_2_microseconds - 8));
                    }else (src_to_dst_num_of_2_microseconds < 8){
                        // src_to_dst_bytes_speed << 8, namely (A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000 >> 3) << 8
                        bits_per_second_src_to_dst_register.write(current_flow_id,(A_current_flow_transmitted_byte + ((bit<32>)hdr.ipv4.totalLen))*1000000 << ( 8 - src_to_dst_num_of_2_microseconds));
                    }*/