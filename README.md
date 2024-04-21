# FlowRecorder

```
+--+      +--+     ++-+
|h1+------+s1+-----+h2+
+--+      +  +     +--+


```

Simple example of direct and indirect counters that count the packets and bytes arriving at each ingress port.


## How to run

Run the topology, by starting either the direct or indirect examples:

```
make 
```



### Using a simple control plane to read the counters

The following controller program will establish a connection with the switch
and through a thrift API it will read all the counter values.

open another terminal using 'help'
```
$ simple_switch_CLI --thrift-port 9090

$ help
$ register_read ingress_port_counter
$ register_read egress_port_counter
$ register_read sys_port_register
```

### Using Wireshark
### Filter ip.dst==10.0.2.2 || ip.dst==10.0.1.1

### ab Apache (simpler & lightweight) benchmark http method 
### J meter (powerful complex)

### configure server
sudo python -m http.server 80 &
### CPU limit on the server 
### check pid :
ps aux
### limit pid:
sudo cpulimit -p [PID] -l 20


### Time window


### Aim to overload the server
### 

### NetFlow 
### Hash 


