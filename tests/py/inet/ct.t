:input;type filter hook input priority 0
:ingress;type filter hook ingress device lo priority 0

*inet;test-inet;input

meta nfproto ipv4 ct original saddr 1.2.3.4;ok;ct original ip saddr 1.2.3.4
ct original ip6 saddr ::1;ok

ct original ip daddr 1.2.3.4 accept;ok

# missing protocol context
ct original saddr ::1;fail

# wrong protocol context
ct original ip saddr ::1;fail
