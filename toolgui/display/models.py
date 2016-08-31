from django.db import models

class trace_file(models.Model):
    docfile = models.FileField(upload_to='trace_files/')
    uploaded_on = models.DateTimeField(null=True, blank=True)

class packet_tf(models.Model):
    packet_num = models.IntegerField(null=True, blank=True)
    Ether_src_macaddr = models.CharField(max_length=17, null=True, blank=True)
    Ether_dst_macaddr = models.CharField(max_length=17, null=True, blank=True)
    Ether_type = models.IntegerField(null=True, blank=True)
    
    IP_src_address = models.CharField(max_length=16, null=True, blank=True)
    IP_dst_address = models.CharField(max_length=16, null=True, blank=True)
    IP_version = models.CharField(max_length=4, null=True, blank=True)
    IP_ihl = models.CharField(max_length=4, null=True, blank=True)
    IP_tos = models.IntegerField(null=True, blank=True)
    IP_length = models.IntegerField(null=True, blank=True)
    IP_id = models.IntegerField(null=True, blank=True)
    IP_flags = models.CharField(max_length=4, null=True, blank=True)
    IP_frag = models.CharField(max_length=4, null=True, blank=True)
    IP_ttl = models.IntegerField(null=True, blank=True)
    IP_proto = models.IntegerField(null=True, blank=True)
    IP_chksum = models.IntegerField(null=True, blank=True)
    
    TCP_sport = models.IntegerField(null=True, blank=True)
    TCP_dport = models.IntegerField(null=True, blank=True)
    TCP_seq = models.CharField(max_length=11, null=True, blank=True)  #int or char?
    TCP_ack = models.CharField(max_length=11, null=True, blank=True)  #int or char?
    TCP_dataofs = models.CharField(max_length=4, null=True, blank=True)
    TCP_reserved = models.CharField(max_length=4, null=True, blank=True)
    TCP_flags = models.CharField(max_length=4, null=True, blank=True)
    TCP_window = models.IntegerField(null=True, blank=True)
    TCP_chksum = models.IntegerField(null=True, blank=True)
    TCP_urgptr = models.IntegerField(null=True, blank=True)
    
    Raw_load = models.CharField(max_length=8192, blank=True, null=True)
    class Meta:
        db_table = "packet"
        ordering = ['pk']