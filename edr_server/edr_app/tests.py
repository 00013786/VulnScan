from django.test import TestCase, Client
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth.models import User
from .models import Client as EDRClient, Process, Port, SuspiciousActivity, Vulnerability
import json
from django.utils import timezone

class EDRClientTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_superuser('admin', 'admin@test.com', 'admin123')
        self.client = EDRClient.objects.create(
            hostname="test-host",
            ip_address="127.0.0.1",
            last_seen=timezone.now()
        )

    def test_client_creation(self):
        self.assertEqual(self.client.hostname, "test-host")
        self.assertEqual(self.client.ip_address, "127.0.0.1")
        self.assertTrue(self.client.last_seen is not None)

class APIEndpointTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_superuser('admin', 'admin@test.com', 'admin123')
        self.client.force_authenticate(user=self.user)
        
        self.client_instance = EDRClient.objects.create(
            hostname="test-host",
            ip_address="127.0.0.1"
        )
        self.test_data = {
            "hostname": "test-host",
            "processes": [
                {
                    "pid": 1234,
                    "name": "test.exe",
                    "path": "C:\\test.exe",
                    "commandLine": "test.exe --param"
                }
            ],
            "ports": [
                {
                    "port": 8080,
                    "protocol": "TCP",
                    "state": "LISTEN",
                    "processName": "test.exe",
                    "pid": 1234
                }
            ],
            "alerts": [
                {
                    "type": "SUSPICIOUS_PROCESS",
                    "description": "Suspicious process detected",
                    "timestamp": "2023-01-01T00:00:00Z",
                    "processName": "test.exe",
                    "pid": 1234
                }
            ]
        }

    def test_data_upload_endpoint(self):
        url = reverse('upload_data')
        response = self.client.post(url, self.test_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify data was saved
        self.assertEqual(Process.objects.count(), 1)
        self.assertEqual(Port.objects.count(), 1)
        self.assertEqual(SuspiciousActivity.objects.count(), 1)

    def test_invalid_data_upload(self):
        url = reverse('upload_data')
        invalid_data = {"hostname": "test-host"}  # Missing required fields
        response = self.client.post(url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class ViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser('admin', 'admin@test.com', 'admin123')
        self.client.login(username='admin', password='admin123')
        
        self.edr_client = EDRClient.objects.create(
            hostname="test-host",
            ip_address="127.0.0.1"
        )
        self.process = Process.objects.create(
            client=self.edr_client,
            pid=1234,
            name="test.exe",
            path="C:\\test.exe",
            command_line="test.exe --param"
        )
        self.port = Port.objects.create(
            client=self.edr_client,
            port_number=8080,
            protocol="TCP",
            state="LISTEN",
            process_name="test.exe",
            process_id=1234
        )
        self.alert = SuspiciousActivity.objects.create(
            client=self.edr_client,
            type="SUSPICIOUS_PROCESS",
            description="Suspicious process detected",
            process_name="test.exe",
            process_id=1234,
            timestamp=timezone.now()
        )

    def test_dashboard_view(self):
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard.html')

    def test_processes_view(self):
        response = self.client.get(reverse('processes'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'processes.html')
        self.assertContains(response, "test.exe")

    def test_ports_view(self):
        response = self.client.get(reverse('ports'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'ports.html')
        self.assertContains(response, "8080")

    def test_alerts_view(self):
        response = self.client.get(reverse('alerts'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'alerts.html')
        self.assertContains(response, "SUSPICIOUS_PROCESS")
