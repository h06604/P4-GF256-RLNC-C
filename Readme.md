## virtual network interface

sudo ip link add name p4-c mtu 1500 type veth

sudo gedit /etc/network/interfaces

auto p4-c
iface p4-c inet static
address 192.168.0.3
netmask 255.255.255.0

sudo /etc/init.d/networking restart

sudo ifconfig p4-c up

sudo ifconfig p4-c down

sudo ip link delete p4-c
## network namespace

### create
sudo ip netns add net0
sudo ip netns add net1

### bash
sudo ip netns exec net0 bash
sudo ip netns exec net1 bash

### create vitrual network interface pair
sudo ip link add type veth

### move network interface(real & virtual) into netns
sudo ip link set veth0 netns net0
sudo ip link set enx00051bc0004e netns net0

sudo ip link set veth1 netns net1
sudo ip link set enxd037453bce75 netns net1

### setup
#### In net0 bash
ip link set veth0 up
ip link set enx00051bc0004e up
#### In net1 bash
ip link set veth1 up
ip link set enxd037453bce75 up

## p4c
cd /home/p4/tutorials_application/vm/p4c

p4c-bm2-ss /home/p4/P4+C/123.p4 -o /home/p4/P4+C/123.json


## bmv2

cd /home/p4/tutorials_application/vm/behavioral-model/targets/simple_switch
sudo ./simple_switch --log-console -i 1@enp0s8 -i 2@enp0s9 /home/p4/P4+C/123.json

sudo sudo ip netns exec net0 bash

sudo ./simple_switch --log-console -i 1@enx00051bc0004e -i 2@veth0 /home/p4/P4+C/123.json

## P4Runtime
cd /home/p4/P4+C/

sudo ip netns exec net0 bash

sudo /home/p4/tutorials_application/vm/behavioral-model/targets/simple_switch/simple_switch_CLI --thrift-port 9090 < /home/p4/P4+C/entry.txt