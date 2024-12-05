from django.urls import path
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('device/<int:device_id>/', views.device_detail, name='device_detail'),
    path('processes/', views.processes, name='processes'),
    path('ports/', views.ports, name='ports'),
    path('alerts/', views.alerts, name='alerts'),
    path('vulnerabilities/', views.vulnerabilities, name='vulnerabilities'),
    path('api/upload/', views.upload_data, name='upload_data'),
]

urlpatterns += router.urls
