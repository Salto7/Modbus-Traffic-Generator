#! /usr/bin/env python
#!/usr/bin/python

##################################################################################
##                                                                              ##
##              Modbus Traffic Generation tool tool                             ##
##              see http://sourceforge.net/projects/modbus-traffic-generator/   ##
##              for more informations                                           ##
##                                                                              ##
## Copyright (C) 2013	Omar Abuljaleel  <100031446@kustar.ac.ae> 		##
##			Khaled salah  <khaled.salah@kustar.ac.ae>               ##
##			Rami Al-Dalky  <rami.aldalky@kustar.ac.ae> 		##
## This program is free software; you can redistribute it and/or modify it	##
##                                                                         	##
## This program is distributed in the hope that it will be useful, but     	##
## WITHOUT ANY WARRANTY; without even the implied warranty of              	##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.				##
##                                                                         	##
##################################################################################

import logging
logging.getLogger("scapy").setLevel(1)
from scapy import *
from ModLib import *
import random;
import sys;
os.system('clear');
if len(sys.argv) <2:
	print 'missing target default IP !';
	print 'terminating program ...';
	sys.exit();
class Rule:
        'scada rule attributes container'
        byte_depth=0;
        byte_offset=0;
        content="";
        def __init__(self, src_ip, src_port,dst_ip,dst_port):
                self.src_ip = src_ip
                self.src_port = src_port
                self.dst_ip=dst_ip
                self.dst_port=dst_port
        def display(self):
                print("src ip is",self.src_ip);
                print("src port is",self.src_port);
                print("dst ip is ",self.dst_ip);
                print("dst port is",self.dst_port);


def send_now(rule_container):
	# IP for all transmissions
	ip = IP(dst=str(sys.argv[1]))
	if rule_container.src_ip !='$EXTERNAL_NET' :
		ip.src=rule_container.src_ip;
	if rule_container.dst_ip !='$HOME_NET' :
		ip.dst=rule_container.dst_ip;
	ip;
	# Sets up the session with a TCP three-way handshake
	# Send the syn, receive the syn/ack
	tcp = TCP( flags = 'S', window = 65535, sport = RandShort(), dport= 502, options = [('MSS', 1360 ), ('NOP', 1), ('NOP', 1), ('SAckOK', '')])
	if rule_container.src_port !="ANY":
		tcp.sport=rule_container.src_port;
	synAck = sr1 ( ip / tcp )

	# Send the ack
	tcp.flags = 'A'
	tcp.sport = synAck[TCP].dport
	tcp.seq = synAck[TCP].ack
	tcp.ack = synAck[TCP].seq + 1
	tcp.options = ''
	send( ip / tcp )
	# Creates and sends the Modbus Read Holding Registers command packet
	# Send the ack/push i.e. the request, receive the data i.e. the 	response
	tcp.flags = 'AP'
	tcp = tcp / adu
	data = sr1(( ip / tcp / data2 ), timeout = 2)
	data.show2()
def parse(rule_container):
	global data2;
	global adu;
	global pdu;
        data2="";
	adu = ModbusADU()
	pdu =  ModbusPDU03_Read_Holding_Registers()
	data=rule_container.content.split();
	print data;
	if rule_container.byte_offset <=0:
		print ("no change");
        elif int(rule_container.byte_offset,10) <13:
                print("change in header")
		print("offset",rule_container.byte_offset);
		for i in range(int(rule_container.byte_offset,10),12):
			print i;
			if i>=12:
				break;
			if len(data)<=0:
				break;
			else:
				if i==0:
					print ("should change transId")
					if len(data)>1:
						adu.transId=int(data[0]+data[1],16);
						data.pop(0);
						data.pop(0);
						i=i+1;
						continue;
					elif len(data)==1:
						adu.transId=int('00'+data[0],16);
						data.pop(0);
						i=i+1;
						continue;
				if i==1:
						adu.transId=int('00'+data[0],16);
						data.pop(0);
				if i==2:
					print ("should change protoId")
					if len(data)>1:
						adu.protoId=int(data[0]+data[1],16);
						data.pop(0);
						data.pop(0);
						i=i+1;
						continue;
					elif len(data)==1:
						adu.protoId=int('00'+data[0],16);
						data.pop(0);
						i=i+1;
						continue;
				if i==3:
						adu.protoId=int('00'+data[0],16);
						data.pop(0);
				if i==4:
					print ("should change adu len")
					if len(data)>1:
						adu.len=int(data[0]+data[1],16);
						data.pop(0);
						data.pop(0);
						i=i+1;
						continue;
					elif len(data)==1:
						adu.len=int('00'+data[0],16);
						data.pop(0);
						i=i+1;
						continue;
				if i==5:
						adu.len=int('00'+data[0],16);
						data.pop(0);
				if i==6:
					print ("should change unitId")
					adu.unitId=int(data[0],16);
					data.pop(0);
				if i==7:
					print ("should change funcCode")
					pdu.funcCode=int(data[0],16);
					data.pop(0);
				if i==8:
					print ("should change startAddr")
					if len(data)>1:
						pdu.startAddr=int(data[0]+data[1],16);
						data.pop(0);
						data.pop(0);
						i=i+1;
						continue;
					else:
						pdu.startAddr=int('00'+data[0],16);
						data.pop(0);
						i=i+1;
						continue;
				if i==9:
						pdu.startAddr=int('00'+data[0],16);
						data.pop(0);

				if i==10:
					print ("should change quantity")
					if len(data)>1:
						pdu.quantity=int(data[0]+data[1],16);
						data.pop(0);
						data.pop(0);
						i=i+1;
						continue;
					elif len(data)==1:
						pdu.quantity=int('00'+data[0],16);
						data.pop(0);
						i=i+1;
						continue;
				if i==11:
						pdu.quantity=int('00'+data[0],16);
						data.pop(0);
		if len(data)>0:
			print("left over",data);
			for k in data:
				data2+=chr(int(k,16));
	else:
		print ("payload");
                for i in range(1,int(rule_container.byte_offset)):
                        data2+=chr(random.randint(0,128));
                payload=rule_container.content.split();
                for ch in payload:
                 data2+=chr(int(ch,16));
               # print data2;
	adu = adu / pdu
	adu.show();
	send_now(rule_container);

def extract_info(line):
        sep_1=line.find("(");
        part_one=line[:sep_1];
        ip_header=part_one.split();
        x=Rule(ip_header[2],ip_header[3],ip_header[5],ip_header[6]);
	if x.dst_port!='502':
		print 'none modbus rule';
		return;
        part_two=line[sep_1+1:line.rfind(")")]
        attrs=part_two.split(';');
        matching = [s for s in attrs if "content:" in s]
        if not matching or attrs.index(matching[len(matching)-1])==0:
                print("not payload checking");
        else:
                tmp=matching[len(matching)-1]
                content=tmp[tmp.find("|")+1:tmp.rfind("|")];
                x.content=content;
                matching = [s for s in attrs if "offset:" in s]
                if len(matching) >0 and attrs.index(matching[len(matching)-1])!=0:     
                        tmp=matching[len(matching)-1]
                        x.byte_offset=tmp[tmp.find(":")+1:]
                        matching = [s for s in attrs if "offset:" in s]
                        if len(matching) >0 and attrs.index(matching[len(matching)-1])!=0 and len(matching[len(matching)-1])<10 :      
                                tmp=matching[len(matching)-1]
                                x.byte_offset=tmp[tmp.find(":")+1:]
                print "content is",x.content," in offset of ",x.byte_offset," and depth of ",x.byte_depth ;
                parse(x);  
with open("scada.rules") as fileobject:
    for line in fileobject:
        extract_info(line);
