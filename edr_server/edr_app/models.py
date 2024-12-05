from django.db import models

# Create your models here.

class Client(models.Model):
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"

class Process(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='processes')
    pid = models.IntegerField()
    name = models.CharField(max_length=255)
    path = models.CharField(max_length=1024)
    command_line = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} (PID: {self.pid})"

class Port(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='ports')
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=10)
    state = models.CharField(max_length=20)
    process_name = models.CharField(max_length=255)
    process_id = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.protocol}:{self.port_number} ({self.state})"

class SuspiciousActivity(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='activities')
    type = models.CharField(max_length=100)
    description = models.TextField()
    process_name = models.CharField(max_length=255, blank=True)
    process_id = models.IntegerField(null=True, blank=True)
    timestamp = models.DateTimeField()

    def __str__(self):
        return f"{self.type} - {self.description[:50]}"

class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    severity = models.CharField(max_length=20)
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()
    related_processes = models.ManyToManyField(Process, related_name='vulnerabilities')

    def __str__(self):
        return self.cve_id
