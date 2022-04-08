:input;type filter hook input priority 0

*ip;test-ip;input

meter xyz size 8192 { ip saddr timeout 30s counter};ok
