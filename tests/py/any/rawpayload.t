:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0
:egress;type filter hook egress device lo priority 0

*inet;test-inet;input
*netdev;test-netdev;ingress,egress

meta l4proto { tcp, udp, sctp} @th,16,16 { 22, 23, 80 };ok;meta l4proto { 6, 17, 132} th dport { 22, 23, 80}
meta l4proto tcp @th,16,16 { 22, 23, 80};ok;tcp dport { 22, 23, 80}
@nh,8,8 0xff;ok
@nh,8,16 0x0;ok

# out of range (0-1)
@th,16,1 2;fail

@ll,0,0 2;fail
@ll,0,1;fail
@ll,0,1 1;ok;@ll,0,8 & 0x80 == 0x80
@ll,0,8 & 0x80 == 0x80;ok
@ll,0,128 0xfedcba987654321001234567890abcde;ok

@ih,32,32 0x14000000;ok
