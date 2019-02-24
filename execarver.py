import optparse
import os.path
from scapy.all import *

def print_carved_file_data(payload, array):
	metadata=""
	b=payload.find("filename")
	e=payload.find("MZ")
	e=e+1
	metadata=payload[b:e+1]
	l=metadata.split('\r')
	filename_exe = l[0][l[0].find("''")+2:]
	array.append(filename_exe)
	file_size = l[1][l[1].find("Content-Length:"):]
	print
	#print l
	print "Filename: " +filename_exe+" "+file_size

parser = optparse.OptionParser()
parser.add_option("-i", "--interface", type="string", help="interface", dest="iface", default="eth0")
parser.add_option("-r", "--tracefile", type="string", help="tracefile", dest="tracefile", default=None)

opts, args = parser.parse_args()

if opts.tracefile is not None:
	print "Tracefile: "+opts.tracefile
	if not os.path.exists(opts.tracefile):
		print "File does not exist!"
		quit()
	filt = " ".join(args)
	pkts = sniff(offline=opts.tracefile, filter=filt)
	sessions = pkts.sessions()
	chosen_keys = []


	for key, pkts in sessions.iteritems():

		for p in pkts:
			if p.haslayer(TCP):
				pload=str(p.getlayer(TCP).payload)
				#dport= p.getlayer(TCP).dport
				if "filename" in pload and "MZ" in pload:
					new_file_metadata=[]
					print_carved_file_data(pload,new_file_metadata)
					new_file_metadata.append(key)
					chosen_keys.append(new_file_metadata)

	for key in chosen_keys:
		packets = sessions[key[1]]
		data_exe=""
		for pkt in packets[1:]:
			data_exe+=str(pkt.getlayer(TCP).payload)
		data_exe = data_exe[data_exe.find("MZ"):]
		f = open(key[0], "w")
		f.write(data_exe)
		f.close()

else:
	filt = " ".join(args)
	pkts = sniff(iface=opts.iface, filter=filt)
	sessions = pkts.sessions()
	chosen_keys = []

	for key, pkts in sessions.iteritems():

		for p in pkts:
			if p.haslayer(TCP):
				pload=str(p.getlayer(TCP).payload)
				#dport= p.getlayer(TCP).dport
				if "filename" in pload and "MZ" in pload:
					new_file_metadata=[]
					print_carved_file_data(pload,new_file_metadata)
					new_file_metadata.append(key)
					chosen_keys.append(new_file_metadata)

	for key in chosen_keys:
		packets = sessions[key[1]]
		data_exe=""
		for pkt in packets[1:]:
			data_exe+=str(pkt.getlayer(TCP).payload)
		data_exe = data_exe[data_exe.find("MZ"):]
		f = open(key[0], "w")
		f.write(data_exe)
		f.close()
