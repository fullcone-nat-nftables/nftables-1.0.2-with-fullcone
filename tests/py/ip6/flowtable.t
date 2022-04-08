:input;type filter hook input priority 0

*ip6;test-ip6;input

meter acct_out size 4096 { meta iif . ip6 saddr timeout 600s counter };ok;meter acct_out size 4096 { iif . ip6 saddr timeout 10m counter }
meter acct_out size 12345 { ip6 saddr . meta iif timeout 600s counter };ok;meter acct_out size 12345 { ip6 saddr . iif timeout 10m counter }
