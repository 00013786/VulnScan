from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
import requests
import json
from .models import Client, Process, Port, SuspiciousActivity, Vulnerability
from .serializers import (
    ClientSerializer, ProcessSerializer, PortSerializer,
    SuspiciousActivitySerializer, VulnerabilitySerializer
)

@login_required
def dashboard(request):
    # Get all active clients (seen in last 5 minutes)
    active_threshold = timezone.now() - timezone.timedelta(minutes=5)
    clients = Client.objects.filter(last_seen__gte=active_threshold).order_by('-last_seen')
    
    inactive_clients = Client.objects.filter(last_seen__lt=active_threshold).order_by('-last_seen')

    context = {
        'active_clients': clients,
        'inactive_clients': inactive_clients,
    }
    return render(request, 'dashboard.html', context)

@login_required
def device_detail(request, device_id):
    client = get_object_or_404(Client, id=device_id)
    
    # Get the latest processes and ports for this client
    processes = Process.objects.filter(client=client).order_by('-timestamp')[:100]
    ports = Port.objects.filter(client=client).order_by('-timestamp')[:100]
    alerts = SuspiciousActivity.objects.filter(client=client).order_by('-timestamp')[:100]
    
    context = {
        'client': client,
        'processes': processes,
        'ports': ports,
        'alerts': alerts,
    }
    return render(request, 'device_detail.html', context)

@login_required
def processes(request):
    context = {
        'processes': Process.objects.all().order_by('-timestamp')
    }
    return render(request, 'processes.html', context)

@login_required
def ports(request):
    context = {
        'ports': Port.objects.all().order_by('-timestamp')
    }
    return render(request, 'ports.html', context)

@login_required
def alerts(request):
    context = {
        'alerts': SuspiciousActivity.objects.all().order_by('-timestamp')
    }
    return render(request, 'alerts.html', context)

@login_required
def vulnerabilities(request):
    context = {
        'vulnerabilities': Vulnerability.objects.all().order_by('-published_date')
    }
    return render(request, 'vulnerabilities.html', context)

@api_view(['POST'])
def upload_data(request):
    try:
        hostname = request.data.get('hostname')
        if not hostname:
            return Response(
                {'error': 'Hostname is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate required data
        if not any(key in request.data for key in ['processes', 'ports', 'alerts']):
            return Response(
                {'error': 'At least one of processes, ports, or alerts is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        client, created = Client.objects.get_or_create(
            hostname=hostname,
            defaults={'ip_address': request.META.get('REMOTE_ADDR', '0.0.0.0')}
        )

        # Update client's last_seen timestamp
        client.last_seen = timezone.now()
        client.save()

        # Process the reported processes
        if 'processes' in request.data:
            for proc_data in request.data['processes']:
                # Validate required process fields
                if not all(key in proc_data for key in ['pid', 'name']):
                    return Response(
                        {'error': 'Process data must include pid and name'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                Process.objects.create(
                    client=client,
                    pid=proc_data['pid'],
                    name=proc_data['name'],
                    path=proc_data.get('path', ''),
                    command_line=proc_data.get('commandLine', '')
                )

        # Process the reported ports
        if 'ports' in request.data:
            for port_data in request.data['ports']:
                # Validate required port fields
                if not all(key in port_data for key in ['port', 'protocol', 'state']):
                    return Response(
                        {'error': 'Port data must include port, protocol, and state'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                Port.objects.create(
                    client=client,
                    port_number=port_data['port'],
                    protocol=port_data['protocol'],
                    state=port_data['state'],
                    process_name=port_data.get('processName', ''),
                    process_id=port_data.get('pid', 0)
                )

        # Process the reported alerts
        if 'alerts' in request.data:
            for alert_data in request.data['alerts']:
                # Validate required alert fields
                if not all(key in alert_data for key in ['type', 'description']):
                    return Response(
                        {'error': 'Alert data must include type and description'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                SuspiciousActivity.objects.create(
                    client=client,
                    type=alert_data['type'],
                    description=alert_data['description'],
                    process_name=alert_data.get('processName', ''),
                    process_id=alert_data.get('pid'),
                    timestamp=timezone.now()
                )

        return Response({'status': 'success'})
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

class ClientViewSet(viewsets.ModelViewSet):
    queryset = Client.objects.all()
    serializer_class = ClientSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def report(self, request, pk=None):
        try:
            client = self.get_object()
            data = request.data

            # Update client's last_seen timestamp
            client.last_seen = timezone.now()
            client.save()

            # Process the reported processes
            if 'processes' in data:
                for proc_data in data['processes']:
                    Process.objects.create(
                        client=client,
                        pid=proc_data['pid'],
                        name=proc_data['name'],
                        path=proc_data.get('path', ''),
                        command_line=proc_data.get('commandLine', '')
                    )
                    # Check for vulnerabilities
                    self.check_process_vulnerabilities(proc_data['name'])

            # Process the reported ports
            if 'ports' in data:
                for port_data in data['ports']:
                    Port.objects.create(
                        client=client,
                        port_number=port_data['port'],
                        protocol=port_data['protocol'],
                        state=port_data['state'],
                        process_name=port_data['processName'],
                        process_id=port_data['pid']
                    )

            # Process the reported suspicious activities
            if 'activities' in data:
                for activity_data in data['activities']:
                    SuspiciousActivity.objects.create(
                        client=client,
                        type=activity_data['type'],
                        description=activity_data['description'],
                        process_name=activity_data.get('processName', ''),
                        process_id=activity_data.get('pid'),
                        timestamp=timezone.now()
                    )

            return Response({'status': 'success'})
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def check_process_vulnerabilities(self, process_name):
        try:
            # Query NVD API
            headers = {
                'apiKey': settings.NVD_API_KEY
            }
            params = {
                'keywordSearch': process_name
            }
            response = requests.get(
                settings.NVD_API_URL,
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    
                    # Create or update vulnerability
                    vulnerability, created = Vulnerability.objects.get_or_create(
                        cve_id=cve.get('id'),
                        defaults={
                            'description': cve.get('descriptions', [{}])[0].get('value', ''),
                            'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                            'published_date': timezone.now(),
                            'last_modified_date': timezone.now()
                        }
                    )

        except Exception as e:
            print(f"Error checking vulnerabilities: {str(e)}")

    @action(detail=True, methods=['post'])
    def execute_command(self, request, pk=None):
        try:
            client = self.get_object()
            command = request.data.get('command')
            if not command:
                return Response(
                    {'error': 'Command is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # In a real implementation, you would send the command to the client
            # For now, we'll just return a success message
            return Response({
                'status': 'success',
                'message': f'Command sent to client {client.hostname}'
            })
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
