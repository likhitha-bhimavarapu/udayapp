"""
URL configuration for lmspro project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
# users/urls.py

from django.urls import path
from lmsapp import views
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView

urlpatterns = [
    path('register/', views.register, name='register'),
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('add_project/', views.add_project, name='add_project'),
    path('projects/', views.project_list, name='project_list'),
    path('initiate_payment/<int:project_id>/', views.initiate_payment, name='initiate_payment'),
    path('payment_success/', views.payment_success, name='payment_success'),
    path('remove-project/', views.remove_project, name='remove_project'),
    path('add_project/', views.add_project, name='add_project'),
    path('ml/', views.ml_projects, name='ml_projects'),
    path('ml_mini/', views.ml_mini_projects, name='ml_mini_projects'),
    path('python/', views.python_projects, name='python_projects'),
    path('python_mini/', views.python_mini_projects, name='python_mini_projects'),
    path('django/', views.django_projects, name='django_projects'),
    path('django_mini/', views.django_mini_projects, name='django_mini_projects'),
    path('php/', views.php_projects, name='php_projects'),
    path('php_mini/', views.php_mini_projects, name='php_mini_projects'),
    path('purchase-details/', views.purchase_details_view, name='purchase_details'),
    path('azure/', views.azure_projects, name='azure_projects'),
    path('azure_mini/', views.azure_mini_projects, name='azure_mini_projects'),
    path('aws/', views.aws_projects, name='aws_projects'),
    path('aws_mini/', views.aws_mini_projects, name='aws_mini_projects'),
    path('react/', views.react_projects, name='react_projects'),
    path('react_mini/', views.react_mini_projects, name='react_mini_projects'),
    path('flask/', views.flask_projects, name='flask_projects'),
    path('flask_mini/', views.flask_mini_projects, name='flask_mini_projects'),
    path('all_mini/', views.all_mini, name='all_mini'),
    path('home/', views.home, name='home'),
    path('contact/', views.contact, name='contact'),
    path('about/', views.about, name='about'),
    path('feedback/',views.feedback_view, name='feedback'),
    path('callback/',views.callback, name='callback'),
    path('allprojects/',views.allprojects,name="allprojects"),
    path('admindashboard/', views.admindashboard, name='admindashboard'),
    path('projectslist/',views.projects,name="projects"),
    path('projects/edit/<int:project_id>/', views.edit_project, name='edit_project'),
    path('projects/delete/<int:project_id>/', views.delete_project, name='delete_project'),
    path('adminfeed/',views.adminfeed,name="adminfeed"),
    path('userdetails/',views.userdetails,name="userdetails"),
    path('admin_login/', views.admin_login, name='admin_login'),
    path('sorry/', views.sorry, name='sorry'),
    path('password_reset/', views.password_reset_request, name='password_reset_request'),
    path('password_reset_form/', views.password_reset_form, name='password_reset_form'),
    path('my-orders/', views.my_orders, name='my_orders'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('chatbot-api/', views.chatbot_api, name='chatbot_api'),
    path('chatbot/', TemplateView.as_view(template_name='users/chatbot.html'), name='chatbot'),
    path("chat-history/", views.chatbot_history, name="chatbot_history"),
    path("statistics/", views.statistics, name="statistics"),
    path('user-statistics/', views.user_statistics, name='user-statistics'),
    path('project-statistics/', views.project_statistics, name='project_statistics'),
    path('project_category/', views.project_category, name='project_category'),
    
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

