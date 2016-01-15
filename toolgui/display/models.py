from __future__ import unicode_literals

from django.db import models

class trace_file(models.Model):
    docfile = models.FileField(upload_to='trace_files/')
    uploaded_on = models.DateTimeField(null=True, blank=True)

class packet_tf(models.Model):
    packet_num = models.IntegerField(null=True, blank=True)
    src_macaddr = models.CharField(max_length=17, null=True, blank=True)
    dst_macaddr = models.CharField(max_length=17, null=True, blank=True)
    type = models.IntegerField(null=True, blank=True)
    
    src_address = models.CharField(max_length=16, null=True, blank=True)
    dst_address = models.CharField(max_length=16, null=True, blank=True)
    version = models.CharField(max_length=2, null=True, blank=True)
    ihl = models.CharField(max_length=2, null=True, blank=True)
    tos = models.IntegerField(null=True, blank=True)
    length = models.IntegerField(null=True, blank=True)
    id_IP = models.IntegerField(null=True, blank=True)
    flags = models.CharField(max_length=2, null=True, blank=True)
    frag = models.CharField(max_length=2, null=True, blank=True)
    ttl = models.IntegerField(null=True, blank=True)
    proto = models.IntegerField(null=True, blank=True)
    chksum = models.IntegerField(null=True, blank=True)
    
    sport = models.IntegerField(null=True, blank=True)
    dport = models.IntegerField(null=True, blank=True)
    seq = models.CharField(max_length=11, null=True, blank=True)  #int or char?
    ack = models.CharField(max_length=11, null=True, blank=True)  #int or char?
    dataofs = models.CharField(max_length=2, null=True, blank=True)
    reserved = models.CharField(max_length=2, null=True, blank=True)
    flags_TCP = models.CharField(max_length=2, null=True, blank=True)
    window = models.IntegerField(null=True, blank=True)
    chksum_TCP = models.IntegerField(null=True, blank=True)
    urgptr = models.IntegerField(null=True, blank=True)
     
    class Meta:
        db_table = "packet"
        ordering = ['pk']