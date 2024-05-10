# NetFlow
## Required Environment
Python, P4, P4-Utils, Mininet, Tcereplay 
## Network Topology
```
+--+      +--+     ++-+
|h1+------+s1+-----+h2+
+--+      +  +     +--+


```
NetFlow based on BMV2.

## How to run

```
sudo p4run
```

### Using a simple control plane to read the registers

The following controller program will establish a connection with the switch
and through a thrift API it will read xxx register.

open another terminal using 'help'
```
$ simple_switch_CLI --thrift-port 9090

$ help
$ register_read xxx
```
### Using /controller/controller.py to read the registers and export them to out.csv file every 5 seconds
'''
$ python mycontroller.py 
'''
## Using cpu_usage_top.sh to record CPU load to xxx.txt during the implementation
'''
$ sudo ./cpu_usage_top.sh simple_switch xxx.txt
'''

## In the Mininet Network
use the following command to monitor the packet flow's throughput and packet loss
'''
$ s1 wireshark &
'''
use the following command to locate the host 1
'''
$ xterm h1
'''
   ## At the Host 1
   use the following command to send desired packets (xxx.pacap) to Host 2 with specific speed packets/second
   '''
   $ tcereplay -i h1-eth0 -p speed xxx.pcap
   '''

## Using the cal_avg_cpu_load.py to calculate the average CPU load during the implementation
'''
$ python cal_avg_cpu_load.py 
'''



