import sys,socket
from scapy.all import *
from datetime import datetime
from time import strftime #For outputting formatted time strings

#This fixes an issue with scapy IPv6 warnings
from logging import getLogger, ERROR 
getLogger("scapy.runtime").setLevel(ERROR)

SYNACK = 0x12 #SYNACK flag constant to check against

mode = "tcp"
host = "local"
port = "common"

if len(sys.argv) > 1:
 argvnum = 1
 done = False
 while done != True: # loop through args until we process them all
  current_arg = sys.argv[argvnum]
  if current_arg == "-h" or current_arg == "-help": # Help
   print("Usage: scanner.py [-h] [-t] [HOST] [PORT] [PROTOCOL]\n-h: Help\n-t: Traceroute (usage -t example.com); ignores all other flags\nHOST\n-host: Scan host range (usage -h xxx.xxx.xxx.xxx-yyy,zzz,aaa-bbb; must be listed in ascending order)\n-l: Scan the local network (default)\nPORT\n-p: Scan port range (usage -p x-y,z,a-b; must be listed in ascending order)\n-c: Scan common ports (default)\n-a: Scan all ports\nPROTOCOL\n-tcp: Uses TCP protocol in scan (default)\n-udp: Uses UDP protocol in scan\n-icmp: Uses ICMP protocol in scan")
   sys.exit()
  elif current_arg == "-t": # Traceroute
   mode = "trace"
   if len(sys.argv) == 2:
    print("Err: Invalid traceroute target. Please give a valid DNS name or IP address for traceroute. Use the -h command for help.")
    sys.exit()
   else:
    host = sys.argv[2] # Traceroute is only reached as argv[1] and argv[2]
   done = True
  elif current_arg == "-host": #Specific host range
   host = sys.argv[argvnum + 1]
   argvnum += 2
  elif current_arg == "-l": #Local host (default)
   argvnum += 1
  elif current_arg == "-p": #Specific port range
   port = sys.argv[argvnum + 1]
   argvnum += 2
  elif current_arg == "-c": #Common ports (default)
   argvnum += 1
  elif current_arg == "-a": #All ports
   port = "all"
   argvnum += 1
  elif current_arg == "-tcp": #TCP (default)
   argvnum += 1
  elif current_arg == "-udp": #UDP
   mode = "udp"
   argvnum += 1
  elif current_arg == "-icmp": #ICMP
   mode = "icmp"
   argvnum += 1
  if argvnum == len(sys.argv):
   done = True

# Traceroute
if mode == "trace":
 max_hops = 30 #We're using 30 here because it's default on some OSes and I want this to not feel too different
 for i in range(1,max_hops+1):
  ret = sr1(IP(dst=host,ttl=i)/UDP(dport=30000),verbose=0,timeout=5)
  if ret is None:
   break;
  elif ret.type == 3: # Target reached
   print str(i)+": "+str(ret.src)
   break;
  else:
   print str(i)+": "+str(ret.src)
 print "Done"
else:
 # Clean up host/port
 hosts = []
 if host != "local": # Interpret manual host param to array
  try:
   if "," in host: # List of IPs (and IP ranges)
    hostlist = host.split(",")
    if "-" in hostlist[0]: #If first is a range
     parts = hostlist[0].split("-")
     base_parts = parts[0].split(".")
     parts[0] = base_parts[3]
     base = base_parts[0]+"."+base_parts[1]+"."+base_parts[2]
     hostlist[0] = parts[0]+"-"+parts[1]
    else: #If the first one isn't a range
     base_parts = hostlist[0].split(".")
     hostlist[0] = base_parts[3]
     base = base_parts[0]+"."+base_parts[1]+"."+base_parts[2]
    for h in hostlist:
     if "-" in h: #If it's a range, get the range
      parts = h.split("-")
      for i in range(int(parts[0]),int(parts[1])+1):
       hosts.append(base+"."+str(i))
     else: # If it's not a range, it's a single IP
      hosts.append(base+"."+str(h))
   else: # One IP or IP range
    if "-" in host:
     parts = host.split("-")
     base_parts = parts[0].split(".")
     parts[0] = base_parts[3]
     base = base_parts[0]+"."+base_parts[1]+"."+base_parts[2]
     for i in range(int(parts[0]),int(parts[1])+1):
      hosts.append(base+"."+str(i))
  except:
   print("Err: Incorrect host format. Use the -h command for host formatting information.")
   sys.exit()
 else: # Determine local network
  try:
   hostname = socket.gethostname()
   local_ip = socket.gethostbyname(hostname)
   ip_parts = local_ip.split(".")
   base_ip = ip_parts[0]+"."+ip_parts[1]+"."+ip_parts[2]
   for i in range(0,256): # Scan the entire local subnet
    hosts.append(base_ip+"."+str(i))
  except:
   print("Err: Could not detect local network IP. Please try manual entry using -host (use the -h command for help).")
   sys.exit()

 ports = []
 if port == "common": # If common, just set array to array of common ports
  ports = [1,5,7,18,20,21,22,23,25,29,37,42,43,49,53,69,70,79,80,103,108,109,110,115,118,119,137,139,143,150,156,161,179,190,194,197,389,396,443,444,445,458,546,547,563,569,1080]
 elif port == "all": # If they want all ports, oblige grudgingly
  ports = range(1,65536) 
 else: # Interpret manual port param to array
  try:
   if "," in port: #Multiple ranges of ports
    portlist = port.split(",")
    for p in portlist:
     if "-" in p:
      ends = p.split("-")
      for i in range(int(ends[0]),int(ends[1])+1):
       ports.append(int(i))
     else:
      ports.append(int(p))
   else: # Single port
    if "-" in port: #If it's a range, get the range
     parts = port.split("-")
     for i in range(int(parts[0]),int(parts[1])+1):
      ports.append(i)
    else: #If it's a single port
     ports.append(int(port))
  except:
   print("Err: Incorrect port format. Use the -h command for port formatting information.")
   sys.exit()

 #Test to see if hosts or ports is empty
 if len(hosts) == 0:
  print("Err: Incorrect host format. Use the -h command for host formatting information.")
  sys.exit()
 elif len(ports) == 0:
  print("Err: Incorrect port format. Use the -p command for port formatting information.")
  sys.exit()

#From this point forward, hosts contains an array of IP address strings and ports contains an array of integer ports
#Now, iterate through each host
 conf.verb = 0 #Don't need scapy output
 results = {} #Dictionary for results, uses IP as key
 for current_host in hosts: #Iterate through each host
  is_up = False
  # Check if it's up
  try:
   ping = sr1(IP(dst=current_host)/ICMP())
   is_up = True
  except:
   print("ERR:",current_host," is not up. Trying next host.")
   is_up = False
  if is_up == True: # If the host is up, start scanning ports
   results[current_host] = [] #Create a results dict entry for this host
   if mode == "tcp": #TCP
    for current_port in ports:   
     ack_packet = sr1(IP(dst = current_host)/TCP(dport=current_port,flags="S"),verbose=0,timeout=5)
     if ack_packet:
      flags = ack_packet.getlayer(TCP).flags
      if flags == SYNACK:
       results[current_host].append(current_port)
      rst_packet = IP(dst = current_host)/TCP(dport = current_port,flags="R")
      send(rst_packet)
   elif mode == "udp": #UDP
    for current_port in ports:
     ret_packet = sr1(IP(dst = current_host)/UDP(dport=current_port), verbose=0, timeout=5)
     if ret_packet[Raw]:
      results[current_host].append(current_port)
   else: #ICMP
    for current_port in ports:
     ret_packet = sr1(IP(dst = current_host)/ICMP(type = 8),timeout = 5)
     if ret_packet:
      results[current_host].append(current_port)

 #By this point, we have scanned all of the specified ports on all of the (available) specified hosts

 #Results
 for current_host in hosts: #Iterate through all hosts
  if current_host in results: #If the host was up
   if len(results[current_host]) == 0: #If the host got no results
    print "Host: "+str(current_host)+"  Open "+upper(mode)+" ports: None"
   else: #If the host got results
    print "Host: "+str(current_host)+"  Open "+upper(mode)+" ports: "+str(results[current_host])
  else: #If the host was not up
   print str(current_host)+" is not up"
  
