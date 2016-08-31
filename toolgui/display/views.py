from scapy.all import *
from scapy.utils import rdpcap
from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.core.urlresolvers import reverse
from display.models import packet_tf, trace_file
from display.forms import TraceFileForm
from toolinterface.settings import MEDIA_ROOT
import time
import os

status = "Not Received"
old_host1 = ""
old_host2 = ""
host1 = ""
host2 = ""
check_host = ""
trace_file_pkts = []


def comp_pkt(pkt_rcvd):     
    #Compare the packet with trace file content      
    global status
    print "function called"
    print pkt_rcvd.summary()
    if pkt_rcvd.haslayer(TCP):
        print pkt_rcvd[IP].dst
        if pkt_rcvd[IP].dst == host1:   
            print pkt_rcvd.summary()
            status = "Received"
            print "packet matched"   
#             pkt_rcvd.summary()

def sendpackets(request):
    global status
    global host1
    global host2
    global old_host1
    global old_host2
    global check_host
    global trace_file_pkts
    
    if request.is_ajax():
        if request.GET:
            packet_num = request.GET.get('packet_num')
            packet_num = int(packet_num)
            print "======================================="
            print "Packet Number: %d" %packet_num
            
            saved_pkt = trace_file_pkts[packet_num]
            if(int(packet_num) == 0):
                zeroth_packet = trace_file_pkts[0]
            
                old_host1 = zeroth_packet[IP].src
                old_host2 = zeroth_packet[IP].dst
                
                host_configured = request.GET.get('host')
                if host_configured == "host1":           #host1 -> src, host2 -> dst
                    check_host = old_host1
                elif host_configured == "host2":
                    check_host = old_host2
                    
                host1 = request.GET.get('src')
                host2 = request.GET.get('dst')

            #print check_host
            if saved_pkt[IP].src == check_host:
                del saved_pkt[IP].chksum
                del saved_pkt[TCP].chksum
                #del saved_pkt.src
                #del saved_pkt.dst
                saved_pkt[IP].src = host1
                saved_pkt[IP].dst = host2
                
                print saved_pkt.summary()
                time.sleep(0.5)
                sendp(saved_pkt)

                table_row = "<tr><td>" + str(packet_num) + "</td><td>" + saved_pkt[IP].src + "</td><td>" + saved_pkt[IP].dst + "</td><td>" + "Sent" + "</td></tr>" 
                print "======================================="
                return HttpResponse(table_row)  
            
            else:
                print "Sniffing For Packet......."
                status = "Not Received"
#                 filter_str = sniff(lfilter=lambda p: any(proto in p and (p[proto].sport in [80, 23] or p[proto].dport in [80, 23]) and (p[IP].dst in ["199.30.80.32"]) for proto in [TCP]))
                src_filter1 = "(p[IP].src in "
                src_filter2 = "[" + '"' + str(host2) + '"' + "]) "
                src_filter = src_filter1 + src_filter2
                
                dst_filter1 = "(p[IP].dst in "
                dst_filter2 = "[" + '"' + str(host1) + '"' + "]) "
                dst_filter = dst_filter1 + dst_filter2
                
                
                filter_str = 'any(proto in p and ' + src_filter + 'and ' + dst_filter + 'for proto in [TCP])'
                evaluate_sniff = "sniff(count = 1, " + "lfilter = lambda p: " + filter_str + ")"
                rec_pkt = eval(evaluate_sniff)
#                 rec_pkt = sniff(count=1, lfilter = lambda p: filter_str, timeout=None)
#                 rec_pkt = sniff(count=1, lfilter = lambda p: any(proto in p and (p[IP].src in ["192.168.1.210"]) and (p[IP].dst in ["192.168.1.156"]) for proto in [TCP]))
                
                new_pkt = rec_pkt[0]
                            
                print "Packet Received.."            
                status = "Received"
                print new_pkt.summary()

#                     if rec_pkt:
#                         if rec_pkt[0].dst == saved_pkt['IP_dst_address']:
#                             rec_pkt[0].summary()
#                             status = "Received"
#                             break
#                     else:
#                         status = "Not Received"
#                 table_row = "<tr><td>" + str(packet_num) + "</td><td>" + saved_pkt['IP_src_address'] + "</td><td>" + saved_pkt['IP_dst_address'] + "</td><td>" + status + "</td></tr>" 

                table_row = "<tr><td>" + str(packet_num) + "</td><td>" + str(new_pkt[IP].src) + "</td><td>" + str(new_pkt[IP].dst) + "</td><td>" + status + "</td></tr>"                 
                return HttpResponse(table_row)
        
def test(request):
    if request.is_ajax():
        saved_pkt = packet_tf.objects.filter(packet_num=0).values().last()
        Ether_new_pkt = Ether()
        Ether_new_pkt.src = saved_pkt['src_macaddr']
        Ether_new_pkt.dst = saved_pkt['dst_macaddr']
        Ether_new_pkt.type = saved_pkt['type']
        
        IP_new_pkt = IP()
        IP_new_pkt.src = saved_pkt['src_address']
        IP_new_pkt.dst = saved_pkt['dst_address']
            
        TCP_new_pkt = TCP()
        TCP_new_pkt.sport = saved_pkt['sport']
        TCP_new_pkt.dport = saved_pkt['dport']
            
        complete_pkt = (Ether_new_pkt/IP_new_pkt/TCP_new_pkt)

        sendp(complete_pkt)
        
        table_row = "<tr><td>" + "1" + "</td><td>" + IP_new_pkt.src + "</td><td>" + IP_new_pkt.dst + "</td><td>" + "Sent" + "</td></tr>" 
        return HttpResponse(table_row)
    else:
        num_packets = packet_tf.objects.all().count()
        SAVE_PATH = MEDIA_ROOT + '/trace_files/' + "save" + '.pcap'
        pkts = []
    
        for i in range(0,num_packets):
            saved_pkt = packet_tf.objects.filter(packet_num=i).values().last()
                    
            Ether_new_pkt = Ether()
            Ether_new_pkt.src = saved_pkt['Ether_src_macaddr']
            Ether_new_pkt.dst = saved_pkt['Ether_dst_macaddr']
            Ether_new_pkt.type = saved_pkt['Ether_type']
            
            IP_new_pkt = IP()
            IP_new_pkt.src = saved_pkt['IP_src_address']
            IP_new_pkt.dst = saved_pkt['IP_dst_address']
            IP_new_pkt.version = 4L
#             IP_new_pkt.ihl = saved_pkt['IP_ihl']
#             IP_new_pkt.tos = saved_pkt['IP_tos']
#             IP_new_pkt.id = saved_pkt['IP_id']
#             IP_new_pkt.flags = saved_pkt['IP_flags']
#             IP_new_pkt.frag = saved_pkt['IP_frag']
#             IP_new_pkt.ttl = saved_pkt['IP_ttl']
#             IP_new_pkt.proto = saved_pkt['IP_proto']
#             IP_new_pkt.chksum = saved_pkt['IP_chksum']
#             
            TCP_new_pkt = TCP()
            TCP_new_pkt.sport = saved_pkt['TCP_sport']
            TCP_new_pkt.dport = saved_pkt['TCP_dport']
#             TCP_new_pkt.seq = saved_pkt['TCP_seq']
#             TCP_new_pkt.ack = saved_pkt['TCP_ack']
#             TCP_new_pkt.dataofs = saved_pkt['TCP_dataofs']
#             TCP_new_pkt.reserved = saved_pkt['TCP_reserved']
#             TCP_new_pkt.flags = saved_pkt['TCP_flags']
#             TCP_new_pkt.window = saved_pkt['TCP_window']
#             TCP_new_pkt.chksum = saved_pkt['TCP_chksum']
#             TCP_new_pkt.urgptr = saved_pkt['TCP_urgptr']
    
            complete_pkt = (Ether_new_pkt/IP_new_pkt/TCP_new_pkt)
            pkts.append(complete_pkt)
    
    
    return HttpResponse("Hello")

def homepage(request):
    tf = trace_file.objects.count()
    return render(request, "home.html", {'num_trace_files':tf})

def upload_trace(request):
    if request.method == 'POST':
        form = TraceFileForm(request.POST, request.FILES)
        if form.is_valid():
            tfile = trace_file(docfile = request.FILES['docfile'])
            tfile.save()
            
            return HttpResponseRedirect(reverse('display.views.upload_trace'))
    
    else:
        form = TraceFileForm()
        
    trace_files = trace_file.objects.all()
    
    return render(request, 'upload_pcap.html', {'trace_files' : trace_files,
                                                'form' : form})
        

def display_packets(request):
    if request.GET:
        selected_tf = request.GET.get('tf')
    else:
        return HttpResponseRedirect("/home/")
    trace_file = MEDIA_ROOT + '/' + selected_tf    
    print trace_file
    pkts = rdpcap(trace_file)

    if packet_tf.objects.exists():
        packet_tf.objects.all().delete()
        
    newpkts = {}
    
    packet_num = 0;
    for pkt in pkts:
        if pkt.haslayer(TCP):
            if pkt.haslayer(Raw):
                R_load = pkt.load,
            else:
                R_load = ""
            
#             newpkts["packet_num"] = packet_num,
#             newpkts["Ether_src_macaddr"] = pkt.src,
#             newpkts["Ether_dst_macaddr"] = pkt.dst,
#             newpkts["Ether_type"] = pkt.type,
#             newpkts["IP_version"] = pkt[IP].version,
#             newpkts["IP_ihl"] = pkt[IP].ihl,
#             newpkts["IP_tos"] = pkt[IP].tos,
#             newpkts["IP_length"] = pkt[IP].len,
#             newpkts["IP_id"] = pkt[IP].id,
#             newpkts["IP_flags"] = pkt[IP].flags,
#             newpkts["IP_frag"] = pkt[IP].frag,
#             newpkts["IP_ttl"] = pkt[IP].ttl,
#             newpkts["IP_proto"] = pkt[IP].proto,
#             newpkts["IP_chksum"] = pkt[IP].chksum,
#             newpkts["IP_src_address"] = pkt[IP].src,
#             newpkts["IP_dst_address"] = pkt[IP].dst,
#             newpkts["TCP_sport"] = pkt[TCP].sport,
#             newpkts["TCP_dport"] = pkt[TCP].dport,
#             newpkts["TCP_seq"] = pkt[TCP].seq,
#             newpkts["TCP_ack"] = pkt[TCP].ack,
#             newpkts["TCP_dataofs"] =  pkt[TCP].dataofs,
#             newpkts["TCP_reserved"] = pkt[TCP].reserved,
#             newpkts["TCP_flags"] = pkt[TCP].flags,
#             newpkts["TCP_window"] = pkt[TCP].window,
#             newpkts["TCP_chksum"] = pkt[TCP].chksum,
#             newpkts["TCP_urgptr"] = pkt[TCP].urgptr,
# #                                 TCP_options = pkt[TCP].options,
#             newpkts["Raw_load"] = R_load
            
            packet_tf.objects.create(packet_num = packet_num,
                                Ether_src_macaddr = pkt.src,
                                Ether_dst_macaddr = pkt.dst,
                                Ether_type = pkt.type,
                                IP_version= pkt[IP].version,
                                IP_ihl = pkt[IP].ihl,
                                IP_tos = pkt[IP].tos,
                                IP_length = pkt[IP].len,
                                IP_id = pkt[IP].id,
                                IP_flags = pkt[IP].flags,
                                IP_frag = pkt[IP].frag,
                                IP_ttl = pkt[IP].ttl,
                                IP_proto = pkt[IP].proto,
                                IP_chksum = pkt[IP].chksum,
                                IP_src_address = pkt[IP].src,
                                IP_dst_address = pkt[IP].dst,
                                TCP_sport = pkt[TCP].sport,
                                TCP_dport = pkt[TCP].dport,
                                TCP_seq = pkt[TCP].seq,
                                TCP_ack = pkt[TCP].ack,
                                TCP_dataofs =  pkt[TCP].dataofs,
                                TCP_reserved = pkt[TCP].reserved,
                                TCP_flags = pkt[TCP].flags,
                                TCP_window = pkt[TCP].window,
                                TCP_chksum = pkt[TCP].chksum,
                                TCP_urgptr = pkt[TCP].urgptr,
#                                 TCP_options = pkt[TCP].options,
                                Raw_load = R_load
                                )
            packet_num = packet_num + 1
 
    pkts_db = packet_tf.objects.all()
    return render(request, "display_pcap.html", {'packets': pkts_db,
                                                 'trace_file' : trace_file})

def edit_packet(request):
    if request.GET:
        pkt_id = request.GET.get('id')
        pkt_num = request.GET.get('pkt_num')
        trace_file = request.GET.get('tf')
        pkt = packet_tf.objects.filter(id=pkt_id).last()
    
    if request.POST:
        src_macaddr = request.POST.get('src_macaddr')
        dst_macaddr = request.POST.get('dst_macaddr')
        typep = request.POST.get('type')
        src_address = request.POST.get('src_address')
        dst_address = request.POST.get('dst_address')
        ip_length = request.POST.get('length')
        ttl = request.POST.get('ttl')
        sport = request.POST.get('sport')
        dport = request.POST.get('dport')
        tcpflags = request.POST.get('tcpflags')
        tcp_window = request.POST.get('window')
    
#         packet_tf.objects.filter(id=pkt_id).update(Ether_src_macaddr=src_macaddr,
#                                                Ether_dst_macaddr=dst_macaddr,
#                                                Ether_type=typep,
#                                                IP_src_address=src_address,
#                                                IP_length=ip_length,
#                                                IP_ttl=ttl,
#                                                TCP_sport=sport,
#                                                TCP_dport=dport,
#                                                TCP_window=int(tcp_window)
    
        pkts_from_tf = rdpcap(trace_file)
        pkt_num = int(pkt_num)   #list index should be int
        pkt_num = pkt_num - 1

        if src_macaddr:
            pkts_from_tf[pkt_num].src = src_macaddr
        if dst_macaddr:
            pkts_from_tf[pkt_num].dst = dst_macaddr
        if typep:
            pkts_from_tf[pkt_num].type = int(typep)
        if src_address:
            pkts_from_tf[pkt_num][IP].src = src_address
        if dst_address:
            pkts_from_tf[pkt_num][IP].dst = dst_address
        if ip_length:
            pkts_from_tf[pkt_num][IP].length = int(ip_length)
        if ttl:
            pkts_from_tf[pkt_num][IP].ttl = int(ttl)
        if sport:
            pkts_from_tf[pkt_num][TCP].sport = int(sport)
        if dport:
            pkts_from_tf[pkt_num][TCP].dport = int(dport)
        if tcpflags:
            pkts_from_tf[pkt_num][TCP].flags = int(tcpflags)
        if tcp_window:
            pkts_from_tf[pkt_num][TCP].window = int(tcp_window)
        
        wrpcap(trace_file, pkts_from_tf)

        tf_short_path = trace_file.split(MEDIA_ROOT, 1)[1]
        return_url = '/display/?tf=' + tf_short_path
        return HttpResponseRedirect(return_url)

    return render(request, "edit_packet.html", {'pkt': pkt,
                                                'pkt_id': pkt_id,
                                                'pkt_num': pkt_num,
                                                'trace_file': trace_file})
    
def delete_packet(request):
    pkt_id = request.GET.get('id')
    pkt_num = request.GET.get('pkt_num')
    trace_file = request.GET.get('tf')
    packet_tf.objects.filter(id=pkt_id).delete()
    
    pkt_num = int(pkt_num)
    pkt_num = pkt_num - 1
    pkts_from_tf = rdpcap(trace_file)
    del pkts_from_tf[pkt_num]
    wrpcap(trace_file, pkts_from_tf)
    
    tf_short_path = trace_file.split(MEDIA_ROOT, 1)[1]
    return_url = '/display/?tf=' + tf_short_path
    return HttpResponseRedirect(return_url)

def replay(request):
    global trace_file_pkts
    trace_file = request.GET.get('trace_file')
    pkts = packet_tf.objects.all()
    trace_file_pkts = rdpcap(trace_file)
    num_pkts = packet_tf.objects.all().count()
    
    return render(request, "replay.html", {'num_packets' : num_pkts,
                                           'trace_file' : trace_file})
#     return render(request, "replay.html", {'packets' : pkts,
#                                            'num_packets' : num_pkts})

def delete_trace(request):
    if request.GET:
        tf = request.GET.get('tf')
        trace_file.objects.filter(docfile=tf).last().delete()
        
        trace_files = trace_file.objects.all()
    trace_files = trace_file.objects.all()

    return render(request, "delete_pcap.html", {'trace_files' : trace_files})

def save(request):
    if request.method == 'POST':
        file_name = request.POST.get('file_name')
        num_packets = packet_tf.objects.all().count()
        
        SAVE_PATH = MEDIA_ROOT + '/trace_files/' + file_name + '.pcap'
        
        if(os.path.exists(SAVE_PATH)):
            os.remove(SAVE_PATH)
                
        for i in range(0,num_packets):
            saved_pkt = packet_tf.objects.filter(packet_num=i).values().last()
            
            Ether_new_pkt = Ether()
            Ether_new_pkt.src = saved_pkt['Ether_src_macaddr']
            Ether_new_pkt.dst = saved_pkt['Ether_dst_macaddr']
            Ether_new_pkt.type = saved_pkt['Ether_type']
            
            IP_new_pkt = IP()

            IP_new_pkt.src = saved_pkt['IP_src_address']
            IP_new_pkt.dst = saved_pkt['IP_dst_address']
#             IP_new_pkt.version = saved_pkt['IP_version']
#             IP_new_pkt.ihl = saved_pkt['IP_ihl']
#             IP_new_pkt.tos = saved_pkt['IP_tos']
#             IP_new_pkt.id = saved_pkt['IP_id']
#             IP_new_pkt.flags = saved_pkt['IP_flags']
#             IP_new_pkt.frag = saved_pkt['IP_frag']
#             IP_new_pkt.ttl = saved_pkt['IP_ttl']
#             IP_new_pkt.proto = saved_pkt['IP_proto']
#             IP_new_pkt.chksum = saved_pkt['IP_chksum']
#             
            TCP_new_pkt = TCP()
            TCP_new_pkt.sport = saved_pkt['TCP_sport']
            TCP_new_pkt.dport = saved_pkt['TCP_dport']
#             TCP_new_pkt.seq = saved_pkt['TCP_seq']
#             TCP_new_pkt.ack = saved_pkt['TCP_ack']
#             TCP_new_pkt.dataofs = saved_pkt['TCP_dataofs']
#             TCP_new_pkt.reserved = saved_pkt['TCP_reserved']
#             TCP_new_pkt.flags = saved_pkt['TCP_flags']
#             TCP_new_pkt.window = saved_pkt['TCP_window']
#             TCP_new_pkt.chksum = saved_pkt['TCP_chksum']
#             TCP_new_pkt.urgptr = saved_pkt['TCP_urgptr']

            IP_new_pkt.src = saved_pkt['src_address']
            IP_new_pkt.dst = saved_pkt['dst_address']
            IP_new_pkt.version = int(saved_pkt['version'])
            IP_new_pkt.ihl = int(saved_pkt['ihl'])
            IP_new_pkt.tos = saved_pkt['tos']
            IP_new_pkt.id = saved_pkt['id_IP']
            IP_new_pkt.flags = int(saved_pkt['flags'], 16)
            #IP_new_pkt.frag = saved_pkt['frag']
            IP_new_pkt.ttl = saved_pkt['ttl']
            IP_new_pkt.proto = saved_pkt['proto']
            IP_new_pkt.chksum = saved_pkt['chksum']
             
            TCP_new_pkt = TCP()
            TCP_new_pkt.sport = saved_pkt['sport']
            TCP_new_pkt.dport = saved_pkt['dport']
            #TCP_new_pkt.seq = saved_pkt['seq']
            #TCP_new_pkt.ack = saved_pkt['ack']
            #TCP_new_pkt.dataofs = saved_pkt['dataofs']
            #TCP_new_pkt.reserved = saved_pkt['reserved']
            #TCP_new_pkt.flags = saved_pkt['flags_TCP']
            #TCP_new_pkt.window = saved_pkt['window']
            #TCP_new_pkt.chksum = saved_pkt['chksum_TCP']
            #TCP_new_pkt.urgptr = saved_pkt['urgptr']

            Raw_new_pkt = Raw()
            Raw_new_pkt = saved_pkt['Raw_load']
            complete_pkt = (Ether_new_pkt/IP_new_pkt/TCP_new_pkt/Raw_new_pkt)
            if i==0:
                wrpcap(SAVE_PATH, complete_pkt)
                pkts = rdpcap(SAVE_PATH)
            pkts.append(complete_pkt)
        wrpcap(SAVE_PATH, pkts)
    return render(request, "save_pcap.html", {})

