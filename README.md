# Moving Target Defense in SDX


## Setup

* Copy the project directory under pox (~/pox/pox/)

## How to start

    $ cd [project working directory]
    $ sudo python mininet/mtd_mininet.py
    $ pox.py pox.mtd.pox_ctrl

## Test environment

* There are two hosts to simulate two ASes: a1, b1
* a1 runs bgpd to advertise 140.0.0.0/16, 150.0.0.0/8, 160.0.0.0/8, 170.0.0.0/16
* b1 runs bgpd to advertise 110.0.0.0/24
* There is a switch between a1, b1 to simulate an edge router
* A host 100.0.0.7 on a1 to simulate our protected host.

## Run test cases

* Current IP mapping can be found at controller screen.

#### 1. Accessing host via active IP address

    mininext> b1 ping -I110.0.0.11 [current virtual IP of 100.0.0.7]
    ...
    ..
    .
    You could see that this ping should be allowed to reach host for a while.

#### 2. Accessing host via expired IP address

    mininext> b1 ping -I110.0.0.11 [previous virtual IP of 100.0.0.7]
    ...
    ..
    .
    This ping command should receive 100% packet lost.

#### 3. "Simulated" attacks

    mininext> a1 iperf -s -B 100.0.0.7 -p 8000 &
    mininext> b1 iperf -B 110.0.0.11 -p 8000 -i 1 -t 30 -c [current virtual IP of 10.0.0.7]
    ...
    ..
    .
    This flow will start for a second, but its flow entry will be removed by controller after DoS attack has been detected.


