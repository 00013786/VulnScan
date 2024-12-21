from rest_framework import serializers
from .models import Client, Process, Port, SuspiciousActivity, Vulnerability, Log, WindowsEventLog

class ProcessSerializer(serializers.ModelSerializer):
    class Meta:
        model = Process
        fields = ['pid', 'name', 'path', 'command_line', 'timestamp']

class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = ['port_number', 'protocol', 'state', 'process_name', 'process_id', 'timestamp']

class SuspiciousActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = SuspiciousActivity
        fields = ['type', 'description', 'process_name', 'process_id', 'timestamp']

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ['cve_id', 'description', 'severity', 'published_date', 'last_modified_date']

class LogSerializer(serializers.ModelSerializer):
    client_hostname = serializers.CharField(source='client.hostname', read_only=True)
    
    class Meta:
        model = Log
        fields = ['id', 'client', 'client_hostname', 'level', 'message', 'timestamp', 'source']
        read_only_fields = ['id', 'client_hostname', 'timestamp']

class ClientSerializer(serializers.ModelSerializer):
    processes = ProcessSerializer(many=True, read_only=True)
    ports = PortSerializer(many=True, read_only=True)
    activities = SuspiciousActivitySerializer(many=True, read_only=True)

    class Meta:
        model = Client
        fields = ['id', 'hostname', 'ip_address', 'last_seen', 'processes', 'ports', 'activities']

class WindowsEventLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = WindowsEventLog
        fields = ['source', 'provider', 'level', 'event_id', 'message', 'timestamp']
