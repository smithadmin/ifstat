# ifstat

This program looks at an interface and reports on traffic statistics there.  What you get depends on whether you run the program with Super User privileges.  For example:

`$ ./ifstat -i eth0
`warning: packet capture disabled: packet capture needs root or CAP_NET_RAW (try sudo): operation not permitted
`Sampling eth0 for 30s (Ctrl-C to stop early)...

`Traffic statistics for eth0 over 30.021s
`----------------------------------------------------------------
`              Total      Packets         Avg rate    Avg pkt/s   Errors    Drops
`RX        22.75 KiB          142      6.21 Kbit/s          4.7        0        0
`TX        13.60 KiB           73      3.71 Kbit/s          2.4        0        0
`ALL       36.35 KiB          215      9.92 Kbit/s          7.2
`$

If the application is run with sudo (or run as root), one will also get a report with the above -and- Top Connections, Top Ports, and Top Talkers, each sorted by number of packets.

## Requirements

- go 1.21

## Running

- go build -o ifstat .

## Command options (CLI)

-  -d duration              sample duration (e.g. 10s, 1m, 2m30s) (default 30s)
-  -i string                network interface to monitor (e.g. eth0)
-  -interval duration       print live per-interval rates every N (e.g. 5s); 0 disables
-  -list                    list available interfaces and exit
-  -no-capture              skip packet capture (counters only; no root needed)
-  -no-local                omit this interface's own addresses from the top talkers
-  -sort string             rank top-N tables by "packets" or "bytes" (default "packets")
-  -top int                 number of entries in each top-N table (default 10)


## License

- This is released under the MIT license.  Use it as you will, but you must give me credit.
