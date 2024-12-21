"""
URL configuration for edr_server project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from rest_framework import routers
from rest_framework.authtoken import views as token_views
from edr_app import views
from edr_app.views import (
    ClientViewSet, dashboard, processes,
    ports, alerts, vulnerabilities, upload_data,
    device_detail, upload_windows_logs
)

router = routers.DefaultRouter()
router.register(r'clients', ClientViewSet)

def redirect_to_login(request):
    return redirect('login')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('login/', auth_views.LoginView.as_view(template_name='edr_app/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('device/<int:device_id>/', views.device_detail, name='device_detail'),
    path('processes/', views.processes, name='processes'),
    path('ports/', views.ports, name='ports'),
    path('alerts/', views.alerts, name='alerts'),
    path('vulnerabilities/', views.vulnerabilities, name='vulnerabilities'),
    path('api/', include(router.urls)),
    path('api/upload/', views.upload_data, name='upload_data'),
    path('api/logs/windows/', views.upload_windows_logs, name='upload_windows_logs'),
    path('api-token-auth/', token_views.obtain_auth_token),
    path('api-auth/', include('rest_framework.urls')),
    
    # Include all edr_app URLs
    path('', include('edr_app.urls')),
]
