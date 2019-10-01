Pyscan

-h or -help flags show usage

Multiple hosts are specified in the pattern xxx.xxx.xxx.xxx-yyy,aaa,bbb-ccc,etc.
Right now, this only handles up to 256 hosts at once from the same range (so you couldn't scan 192.168.1.0 and 192.168.0.0 at the same time, but you could scan 192.168.0.1-192.168.0.147 in a single scan, for example)

Multiple ports are specified in the pattern a-b,c,d-e,etc.
For example, you could scan ports 17-20,22,23,25,26-80 at the same time

All hosts and ports need to be specified in ascending order.

Traceroute:
-t flag indicates a traceroute, followed by the host name (e.g., pyscan.py -t google.com)
Max 30 hops, timeout of 5 seconds for each hop