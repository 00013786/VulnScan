from rest_framework import serializers
from .models import Client, Process, Port, SuspiciousActivity, Vulnerability

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

class ClientSerializer(serializers.ModelSerializer):
    processes = ProcessSerializer(many=True, read_only=True)
    ports = PortSerializer(many=True, read_only=True)
    activities = SuspiciousActivitySerializer(many=True, read_only=True)

    class Meta:
        model = Client
        fields = ['id', 'hostname', 'ip_address', 'last_seen', 'processes', 'ports', 'activities']
