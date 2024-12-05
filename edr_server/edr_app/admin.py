from django.contrib import admin
from .models import Client, Process, Port, SuspiciousActivity, Vulnerability

# Register your models here.

@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'ip_address', 'last_seen')
    search_fields = ('hostname', 'ip_address')

@admin.register(Process)
class ProcessAdmin(admin.ModelAdmin):
    list_display = ('client', 'pid', 'name', 'timestamp')
    list_filter = ('client',)
    readonly_fields = ('client', 'pid', 'name', 'timestamp')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ('client', 'port_number', 'protocol', 'state', 'timestamp')
    list_filter = ('client', 'protocol', 'state')
    readonly_fields = ('client', 'port_number', 'protocol', 'state', 'timestamp')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

@admin.register(SuspiciousActivity)
class SuspiciousActivityAdmin(admin.ModelAdmin):
    list_display = ('client', 'type', 'description', 'timestamp')
    list_filter = ('client', 'type')

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'severity', 'published_date')
    list_filter = ('severity',)
    search_fields = ('cve_id', 'description')
