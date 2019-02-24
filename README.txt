Program runs by the command:
python execarver.py [-i interface] [-r tracefile] [BPF filter]

If you don't specify anything, it will run in the interface mode with default eth0.
If you just put -i, by default it will still run at eth0
If you put -r, then you have to specify a file. Otherwise, program will abort. 
If you specify both -i and -r then it will read the tracefile by default.
If you put -h, you can see the options.

Sample output for python execarver.py -r tracefile.pcap >> README.txt:

Tracefile: tracefile.pcap

Filename: winamp295.exe Content-Length: 2478784

Filename: utorrent_2.2.1.exe Content-Length: 399224

Here is the sample output to check if the file sizes were read correctly:

ls -l >> README.txt

total 8736
-rw-r--r-- 1 root root    2260 Feb 21 22:17 execarver.py
-rw-r--r-- 1 root root     128 Feb 21 23:28 README.txt
-rw-r--r-- 1 root root 6053222 Feb 21 23:15 tracefile.pcap
-rw-r--r-- 1 root root  399224 Feb 21 23:28 utorrent_2.2.1.exe
-rw-r--r-- 1 root root 2478796 Feb 21 23:28 winamp295.exe

