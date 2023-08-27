# mikrotik-rust-passive-dns

Jank code. Current usage is to simply run and pick an interface.  
What code currently does:

1. Listens for incoming packets with filter `udp src port 53` which are responses from a DNS Server.
2. For every domain in question that was answered, list to an array.
3. Matches entries in the array against the regex `\.discord\.media$`.
4. Replace `discord.media` with `discord.gg` to get real voice IP.
5. Add domain to `/ip/firewall/address-list/add` with timeout of 24h.
