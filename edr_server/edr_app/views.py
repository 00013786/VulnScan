from django.shortcuts import render, get_object_or_404, redirect
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import requests
import json
from .models import Client, Process, Port, SuspiciousActivity, Vulnerability, VulnerabilityMatch, Log
from .serializers import (
    ClientSerializer, ProcessSerializer, PortSerializer,
    SuspiciousActivitySerializer, VulnerabilitySerializer, LogSerializer
)
from .utils import analyze_vulnerabilities
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')

@login_required
def dashboard(request):
    # Get all clients
    all_clients = Client.objects.all()
    
    # Set the threshold for active devices (5 minutes)
    five_minutes_ago = timezone.now() - timedelta(minutes=5)
    
    # Filter active and inactive clients
    active_clients = Client.objects.filter(last_seen__gte=five_minutes_ago)
    inactive_clients = Client.objects.filter(last_seen__lt=five_minutes_ago)
    
    context = {
        'active_clients': active_clients,
        'inactive_clients': inactive_clients,
    }
    return render(request, 'edr_app/dashboard.html', context)

@login_required
def device_detail(request, device_id):
    client = get_object_or_404(Client, id=device_id)
    
    # Get recent data, excluding PID 0
    processes = Process.objects.filter(client=client).exclude(pid=0).order_by('-timestamp')[:50]
    ports = Port.objects.filter(client=client).order_by('-timestamp')[:50]
    alerts = SuspiciousActivity.objects.filter(client=client).order_by('-timestamp')[:20]
    logs = Log.objects.filter(client=client).order_by('-timestamp')[:100]
    
    # Analyze vulnerabilities
    analyze_vulnerabilities(client)
    vulnerability_matches = VulnerabilityMatch.objects.filter(client=client).order_by('-confidence_score')
    
    # Group vulnerabilities by type
    process_vulnerabilities = vulnerability_matches.filter(match_type='PROCESS')
    service_vulnerabilities = vulnerability_matches.filter(match_type='SERVICE')
    port_vulnerabilities = vulnerability_matches.filter(match_type='PORT')
    
    clients = Client.objects.all().order_by('hostname')

    context = {
        'client': client,
        'processes': processes,
        'ports': ports,
        'alerts': alerts,
        'process_vulnerabilities': process_vulnerabilities,
        'service_vulnerabilities': service_vulnerabilities,
        'port_vulnerabilities': port_vulnerabilities,
        'logs': logs,
        'clients': clients,
    }
    return render(request, 'edr_app/device_detail.html', context)

@login_required
def processes(request):
    processes = Process.objects.select_related('client').exclude(pid=0).order_by('-timestamp')
    clients = Client.objects.all().order_by('hostname')
    return render(request, 'edr_app/processes.html', {
        'processes': processes,
        'clients': clients,
    })

@login_required
def ports(request):
    ports = Port.objects.select_related('client').order_by('-timestamp')
    clients = Client.objects.all().order_by('hostname')
    return render(request, 'edr_app/ports.html', {
        'ports': ports,
        'clients': clients,
    })

@login_required
def alerts(request):
    alerts = SuspiciousActivity.objects.all().order_by('-timestamp')[:100]
    context = {
        'alerts': alerts,
    }
    return render(request, 'edr_app/alerts.html', context)

@login_required
def vulnerabilities(request):
    # Get all vulnerability matches with related data
    vulnerabilities = VulnerabilityMatch.objects.select_related(
        'vulnerability', 'client', 'process', 'port'
    ).order_by('-timestamp')

    # Convert confidence scores from 0-1 to 0-100
    for vuln in vulnerabilities:
        vuln.confidence_score = vuln.confidence_score * 100

    context = {
        'vulnerabilities': vulnerabilities,
    }
    return render(request, 'edr_app/vulnerabilities.html', context)

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.contrib.admin.views.decorators import staff_member_required
from .models import Client, Process, Port, SuspiciousActivity, Log
import json
import csv
from datetime import datetime

@staff_member_required
def view_logs(request):
    # Get filter parameters
    level = request.GET.get('level', '')
    client_id = request.GET.get('client', '')
    date_str = request.GET.get('date', '')

    # Start with all logs
    logs = Log.objects.select_related('client').all().order_by('-timestamp')

    # Apply filters
    if level:
        logs = logs.filter(level=level)
    if client_id:
        logs = logs.filter(client_id=client_id)
    if date_str:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date=date)
        except ValueError:
            pass

    # Pagination
    paginator = Paginator(logs, 50)  # Show 50 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'logs': page_obj,
        'log_levels': Log.LOG_LEVELS,
        'clients': Client.objects.all(),
        'selected_level': level,
        'selected_client': client_id,
        'selected_date': datetime.strptime(date_str, '%Y-%m-%d') if date_str else None,
    }
    return render(request, 'edr_app/logs.html', context)

@staff_member_required
def download_logs(request):
    # Get filter parameters
    level = request.GET.get('level', '')
    client_id = request.GET.get('client', '')
    date_str = request.GET.get('date', '')

    # Start with all logs
    logs = Log.objects.select_related('client').all().order_by('-timestamp')

    # Apply filters
    if level:
        logs = logs.filter(level=level)
    if client_id:
        logs = logs.filter(client_id=client_id)
    if date_str:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date=date)
        except ValueError:
            pass

    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="logs.csv"'

    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'Client', 'Level', 'Source', 'Message'])

    # Write data
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.client.hostname,
            log.level,
            log.source,
            log.message
        ])

    return response

@csrf_exempt
def upload_logs(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

    try:
        data = json.loads(request.body)
        logs_data = data.get('logs', [])

        # Get or create client based on hostname
        hostname = logs_data[0].get('hostname') if logs_data else None
        if not hostname:
            return JsonResponse({'error': 'Hostname is required'}, status=400)

        client, _ = Client.objects.get_or_create(
            hostname=hostname,
            defaults={'ip_address': request.META.get('REMOTE_ADDR', '0.0.0.0')}
        )

        # Create logs
        logs_to_create = []
        for log_data in logs_data:
            logs_to_create.append(Log(
                client=client,
                level=log_data.get('level', 'INFO'),
                message=log_data.get('message', ''),
                source=log_data.get('source', ''),
                timestamp=datetime.fromtimestamp(log_data.get('timestamp', 0))
            ))

        Log.objects.bulk_create(logs_to_create)
        return JsonResponse({'message': f'Successfully created {len(logs_to_create)} logs'})

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])  # Allow any client to upload data
def upload_data(request):
    try:
        # Get hostname from request data
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

        # Get or create client
        client, created = Client.objects.get_or_create(
            hostname=hostname,
            defaults={'ip_address': request.META.get('REMOTE_ADDR', '0.0.0.0')}
        )

        # Update client's last_seen timestamp
        client.last_seen = timezone.now()
        client.save()

        # Process the reported processes
        if 'processes' in request.data:
            # First validate all process data
            valid_processes = []
            for proc_data in request.data['processes']:
                if all(key in proc_data for key in ['pid', 'name']):
                    valid_processes.append(proc_data)
                
            # Only delete old processes if we have valid new data
            if valid_processes:
                Process.objects.filter(client=client).delete()  # Clear old processes
                for proc_data in valid_processes:
                    Process.objects.create(
                        client=client,
                        pid=proc_data['pid'],
                        name=proc_data['name'],
                        path=proc_data.get('path', ''),
                        command_line=proc_data.get('commandLine', '')
                    )

        # Process the reported ports
        if 'ports' in request.data:
            Port.objects.filter(client=client).delete()  # Clear old ports
            for port_data in request.data['ports']:
                if not all(key in port_data for key in ['port', 'protocol', 'state']):
                    continue
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
                if not all(key in alert_data for key in ['type', 'description']):
                    continue
                SuspiciousActivity.objects.create(
                    client=client,
                    type=alert_data['type'],
                    description=alert_data['description'],
                    process_name=alert_data.get('processName', ''),
                    process_id=alert_data.get('pid', 0)
                )

        # Analyze vulnerabilities for the updated client data
        analyze_vulnerabilities(client)

        return Response({'status': 'success'})
    except Exception as e:
        print(f"Error in upload_data: {str(e)}")  # Add logging for debugging
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@method_decorator(csrf_exempt, name='dispatch')
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
                    if proc_data['pid'] != 0:  # Skip processes with PID 0
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

            # Analyze vulnerabilities
            analyze_vulnerabilities(client)

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

    @action(detail=True, methods=['post'])
    def logs(self, request, pk=None):
        """
        Endpoint for receiving logs from a client
        """
        client = self.get_object()
        data = request.data
        
        # Create log entry
        log = Log.objects.create(
            client=client,
            level=data.get('level', 'INFO'),
            message=data.get('message', ''),
            source=data.get('source', '')
        )
        
        return Response(LogSerializer(log).data, status=status.HTTP_201_CREATED)
