from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='security_dashboard'),
    path('check/', views.check_access, name='check_access'),
    path('admin/', views.admin_panel, name='admin_panel'),
    path('logs/', views.view_logs, name='view_logs'),
]