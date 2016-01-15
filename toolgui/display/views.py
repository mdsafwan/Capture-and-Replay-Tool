from scapy.all import *
from scapy.utils import rdpcap
from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.core.urlresolvers import reverse
from display.models import packet_tf, trace_file
from display.forms import TraceFileForm
from toolinterface.settings import MEDIA_ROOT

def test(request):
    return render(request, "test.html", {})

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
        trace_file = request.GET.get('tf')
    
    trace_file = MEDIA_ROOT + '/' + trace_file    
    print trace_file
    pkts = rdpcap(trace_file)

    if packet_tf.objects.exists():
        packet_tf.objects.all().delete()
        
    packet_num = 0;
    for pkt in pkts:
        if pkt.haslayer(TCP):
            packet_tf.objects.create(packet_num = packet_num,
                                src_macaddr = pkt.src,
                                dst_macaddr = pkt.dst,
                                type = pkt.type,
                                version = pkt[IP].version,
                                ihl = pkt[IP].ihl,
                                tos = pkt[IP].tos,
                                length = pkt[IP].len,
                                id_IP = pkt[IP].id,
                                flags = pkt[IP].flags,
                                frag = pkt[IP].frag,
                                ttl = pkt[IP].ttl,
                                proto = pkt[IP].proto,
                                chksum = pkt[IP].chksum,
                                src_address = pkt[IP].src,
                                dst_address = pkt[IP].dst,
                                sport = pkt[TCP].sport,
                                dport = pkt[TCP].dport,
                                seq = pkt[TCP].seq,
                                ack = pkt[TCP].ack,
                                dataofs =  pkt[TCP].dataofs,
                                reserved = pkt[TCP].reserved,
                                flags_TCP = pkt[TCP].flags,
                                window = pkt[TCP].window,
                                chksum_TCP = pkt[TCP].chksum,
                                urgptr = pkt[TCP].urgptr
                                )
            packet_num = packet_num + 1
 
    pkts_db = packet_tf.objects.all()
    return render(request, "display_pcap.html", {'packets': pkts_db })

def edit_packet(request):
    pkt_id = request.GET.get('id')
    pkt = packet_tf.objects.filter(id=pkt_id).last()
    
    if request.POST:
        src_macaddr = request.POST.get('src_macaddr')
        dst_macaddr = request.POST.get('dst_macaddr')
        typep = request.POST.get('type')
        src_address = request.POST.get('src_address')
        length = request.POST.get('length')
        ttl = request.POST.get('ttl')
        sport = request.POST.get('sport')
        dport = request.POST.get('dport')
        window = request.POST.get('window')
    
        packet_tf.objects.filter(id=pkt_id).update(src_macaddr=src_macaddr,
                                               dst_macaddr=dst_macaddr,
                                               type=typep,
                                               src_address=src_address,
                                               length=length,
                                               ttl=ttl,
                                               sport=sport,
                                               dport=dport,
                                               window=window)
    
    return render(request, "edit_packet.html", {'pkt': pkt,
                                                'pkt_id': pkt_id})
    
def delete_packet(request):
    pkt_id = request.GET.get('id')
    packet_tf.objects.filter(id=pkt_id).delete()
    
    return HttpResponseRedirect('/display/')

def save(request):
    num_packets = packet_tf.objects.all().count()
    SAVE_PATH = MEDIA_ROOT + '/trace_files/save.pcap'

    
    for i in range(0,num_packets):
        saved_pkt = packet_tf.objects.filter(packet_num=i).values().last()
        
        IP_new_pkt = IP()
        IP_new_pkt.src = saved_pkt['src_address']
        IP_new_pkt.dst = saved_pkt['dst_address']
        
        TCP_new_pkt = TCP()
        TCP_new_pkt.sport = saved_pkt['sport']
        TCP_new_pkt.dport = saved_pkt['dport']
         
        complete_pkt = (IP_new_pkt/TCP_new_pkt)
        if i==0:
            wrpcap(SAVE_PATH, complete_pkt)
            pkts = rdpcap(SAVE_PATH)
        pkts.append(complete_pkt)
    wrpcap(SAVE_PATH, pkts)
    return HttpResponse("Trace Saved!")