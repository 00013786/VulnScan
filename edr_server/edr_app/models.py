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
    version = models.CharField(max_length=50, blank=True, null=True)

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
    service_name = models.CharField(max_length=100, blank=True, null=True)
    service_version = models.CharField(max_length=50, blank=True, null=True)

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
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()
    affected_software = models.CharField(max_length=255, default='Unknown')
    affected_versions = models.CharField(max_length=255, default='*')
    related_processes = models.ManyToManyField(Process, related_name='vulnerabilities', blank=True)
    related_ports = models.ManyToManyField(Port, related_name='vulnerabilities', blank=True)

    def __str__(self):
        return self.cve_id

class VulnerabilityMatch(models.Model):
    MATCH_TYPE_CHOICES = [
        ('PROCESS', 'Process Match'),
        ('PORT', 'Port Match'),
        ('SERVICE', 'Service Match'),
    ]

    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    match_type = models.CharField(max_length=20, choices=MATCH_TYPE_CHOICES)
    process = models.ForeignKey(Process, on_delete=models.CASCADE, null=True, blank=True)
    port = models.ForeignKey(Port, on_delete=models.CASCADE, null=True, blank=True)
    confidence_score = models.FloatField(default=0.0)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [
            ('vulnerability', 'client', 'process'),
            ('vulnerability', 'client', 'port'),
        ]

    def __str__(self):
        return f"{self.vulnerability.cve_id} - {self.match_type} - {self.confidence_score}"

class Log(models.Model):
    LOG_LEVELS = [
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('DEBUG', 'Debug'),
    ]
    
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=10, choices=LOG_LEVELS, default='INFO')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    source = models.CharField(max_length=255, help_text="Source of the log (e.g., component name)")

    def __str__(self):
        return f"[{self.level}] {self.client.hostname}: {self.message[:50]}"

    class Meta:
        ordering = ['-timestamp']
