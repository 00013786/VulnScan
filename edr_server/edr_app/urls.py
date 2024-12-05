from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('processes/', views.processes, name='processes'),
    path('ports/', views.ports, name='ports'),
    path('alerts/', views.alerts, name='alerts'),
    path('vulnerabilities/', views.vulnerabilities, name='vulnerabilities'),
    path('api/upload/', views.upload_data, name='upload_data'),
]
