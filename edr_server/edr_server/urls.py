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
from rest_framework import routers
from edr_app.views import (
    ClientViewSet, dashboard, processes,
    ports, alerts, vulnerabilities, upload_data
)

router = routers.DefaultRouter()
router.register(r'clients', ClientViewSet)

urlpatterns = [
    path('', dashboard, name='dashboard'),
    path('processes/', processes, name='processes'),
    path('ports/', ports, name='ports'),
    path('alerts/', alerts, name='alerts'),
    path('vulnerabilities/', vulnerabilities, name='vulnerabilities'),
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/upload/', upload_data, name='upload_data'),
    path('api-auth/', include('rest_framework.urls')),
]
