from django import forms

class TraceFileForm(forms.Form):
    docfile = forms.FileField(
        label='Click Browse',
        help_text='To select a trace file (.pcap file)'
    )