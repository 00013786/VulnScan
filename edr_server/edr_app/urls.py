from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'api/endpoints', views.ClientViewSet)

urlpatterns = [
    # Web interface endpoints
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('device/<int:device_id>/', views.device_detail, name='device_detail'),
    path('processes/', views.processes, name='processes'),
    path('ports/', views.ports, name='ports'),
    path('alerts/', views.alerts, name='alerts'),
    path('vulnerabilities/', views.vulnerabilities, name='vulnerabilities'),
    path('logs/', views.logs, name='logs'),
    path('logs/view/', views.view_logs, name='view_logs'),
    path('logs/download/', views.download_logs, name='download_logs'),
    
    # API endpoints
    path('api/upload/', views.upload_data, name='upload_data'),
    path('api/logs/upload/', views.upload_logs, name='upload_logs'),
    path('api/logs/windows/', views.upload_windows_logs, name='upload_windows_logs'),
    path('api/clients/<int:client_id>/kill_process/<int:process_id>/', views.kill_process, name='kill_process'),
    path('api/clients/<int:client_id>/command/', views.client_command, name='client_command'),
    path('api/commands/pending/', views.pending_commands, name='pending_commands'),
]

urlpatterns += router.urls
