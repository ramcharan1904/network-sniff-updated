from scapy.all import *

import datetime
import time
import csv
import os

 
def findfile():
    print('finding file')
    file_num=0
    dir='D:\directories'
    NUM_FILE_CHARS=4
    cnt = file_num
    print('starting with', cnt)
    while cnt < 10**NUM_FILE_CHARS:
        file_name = str(cnt).zfill(NUM_FILE_CHARS) + '.csv'
        global file_path
        file_path = os.path.join(dir, file_name)
        if not os.path.exists(file_path):
            break
        cnt += 1
        if cnt > 10**NUM_FILE_CHARS:
            print("directory is full")
                        
    data=["version","ihl","tos","iplen","ip_flags","frag","ttl","chksum","proto","src","dst","tcp_sport","tcp_dport","seq","ack","reserved","tcp_flags","window","tcp_chksum","urgptr","options","udp_sport","udp_dport","Udp_len","udp_chksum","srcmac","destmac","icmp_type","icmp_code","icmp_chksum","hour","minute","day"]
   # with open(file_path,'a',newline="") as p:
    #      writer=csv.writer(p)

     #     writer.writerow(data)


def  print_file(pkt):
    
    print(pkt.summary())

    if(pkt.haslayer(Ether)):
        global data_2
        data_2=[pkt[Ether].src,pkt[Ether].dst]
        
        print(data_2)
        
    else:
        return "ethr layer not found"
        

    if(pkt.haslayer(IP)):
       
        print("##[IP]##")
        print("version =",pkt[IP].version)
        print("ihl =",pkt[IP].ihl)
        print("tos =",pkt[IP].tos)
        print("len =",pkt[IP].len)
        print("flags =",pkt[IP].flags)
        print("frag =",pkt[IP].frag)
        print("ttl =",pkt[IP].ttl)
        print("chksum =",pkt[IP].chksum)
        print ("proto =",pkt[IP].proto)
        print ("src =",pkt[IP].src)
        print ("dst =",pkt[IP].dst)
        
     #   x=pkt[IP].src
      #  y=pkt[IP].dst
       # src_ip=x.split(".")
        #dst_ip=y.split(".")
        
        
        ip_data=[pkt[IP].version,pkt[IP].ihl,pkt[IP].tos,pkt[IP].len,pkt[IP].flags,pkt[IP].frag,pkt[IP].ttl,pkt[IP].chksum,pkt[IP].proto,pkt[IP].src,pkt[IP].dst]
        data_2.extend(ip_data)
    else:
        nonedata="0","0","0","0","0","0","0","0","0","0","0"
        data_2.extend(nonedata)
        
    if(pkt.haslayer(TCP)):
        print("##TCP##")
        print("sport =",pkt[TCP].sport)
        print("dport =",pkt[TCP].dport)
        print("seq =",pkt[TCP].seq)
        print("ack =",pkt[TCP].ack)
        print("reserved =",pkt[TCP].reserved)
        print("flags =",pkt[TCP].flags)
        print("window =",pkt[TCP].window)
        print("chksum =",pkt[TCP].chksum)
        print("urgptr =",pkt[TCP].urgptr)
        print("options =",pkt[TCP].options)
        tcp_data=pkt[TCP].sport,pkt[TCP].dport,pkt[TCP].seq,pkt[TCP].ack,pkt[TCP].reserved,pkt[TCP].flags,pkt[TCP].window,pkt[TCP].chksum,pkt[TCP].urgptr,pkt[TCP].options
        data_2.extend(tcp_data)
        print(data_2)
    
    else:
       # [TCP].sport,pkt[TCP].dport,pkt[TCP].seq,pkt[TCP].ack,pkt[TCP].reserved,pkt[TCP].flags,pkt[TCP].window,pkt[TCP].chksum,pkt[TCP].urgptr,pkt[TCP].options="-----"
        no_data = "0","0","0","0","0","0","0","0","0","0"
        
        data_2.extend(no_data)
        print("new1")
        
        
    if(pkt.haslayer(UDP)):
         print("##UDP##")
         print("sport =",pkt[UDP].sport)
         print("dport =",pkt[UDP].dport)
         print("len =",pkt[UDP].len)
         print("chksum =",pkt[UDP].chksum)
         udp_data=pkt[UDP].sport,pkt[UDP].dport,pkt[UDP].len,pkt[UDP].chksum
         data_2.extend(udp_data)
         

         
         
         
    else:
        nonedata="0","0","0","0"
        data_2.extend(nonedata)
        print("new")
    
   

    if(pkt.haslayer(ICMP)):
    
        icmp_data=pkt[ICMP].code,pkt[ICMP].chksum
        data_2.extend(icmpdata)
    
    else:
        nonedata="0","0","0"
        data_2.extend(nonedata)
    
    write()
        
    
        
    
          

     
    
    

def delay():
 findfile()
 pkt=sniff(filter=" 192.168.43.1/255", count=200,prn=print_file)
 

def write():
    
    print("fox")
    x = datetime.datetime.now()
    time=x.strftime("%H:%M")
    time=time.split(":")
    day=x.strftime("%A")
    day_time=time[0],time[1],day
    data_2.extend(day_time)
    with open(file_path,'a',newline="") as p:
          writer=csv.writer(p)

          writer.writerow(data_2)

 

while True:
    time.sleep(10)
    delay()