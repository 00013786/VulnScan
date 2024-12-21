from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()

urlpatterns = [
    # API endpoints
    path('api/upload/', views.upload_data, name='upload_data'),
    path('api/logs/upload/', views.upload_logs, name='upload_logs'),
    
    # Web interface endpoints
    path('logs/', views.view_logs, name='view_logs'),
    path('logs/download/', views.download_logs, name='download_logs'),
]

urlpatterns += router.urls
