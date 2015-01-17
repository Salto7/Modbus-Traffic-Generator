# Modbus-Traffic-Generator
Modbus Traffic Generator
#########################################################################
##                                                                      #
## Modbus Traffic Generator 						#
##                                                                      #
#########################################################################
##                                                                      #
## Version: 1.0                                                         #
## Date:    12.2.2013                                                  #
##                                                                      #
#########################################################################

DESCRIPTION:
============
This tool Generates Modbus traffic to trigger alerts in Snort Intrusion detection System. It reads Snort rules from "scada.rules" input file,parses the rules and generateS proper packet(s) that would trigger the coresponding rule alerts in the intrusion detection system.


HOW TO RUN:
==========
In order to send IPv4 packets to the network directly from the tool, you must have full privileges on the machine. start by typing command shown below followed by the Target machine IP:

$sudo Python Modbus_traffic_generator.py.py <target Machine IP>

example: $sudo Python Modbus_traffic_generator.py.py 10.20.30.40


PREREQUISITES:
==============
Scapy and Python must be installed on the machine running the tool. Snort IDS must be installed on the target machine or within the network (Running on promiscuous mode).

You can download the latest version of Scapy here: http://www.secdev.org/projects/scapy/
you can download the latest version of Snort IDS here: https://www.snort.org/


