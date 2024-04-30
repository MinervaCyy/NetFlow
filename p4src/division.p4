   /* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
action calculate_division_precise(in bit<32> numerator, in bit<32> denominator, inout bit<32> quotient_integer, inout bit<32> quotientdecimal){
      
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