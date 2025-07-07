
from django.shortcuts import render, redirect,get_object_or_404,HttpResponse
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import Project,  ProjectPurchase, Contact, Feedback
from .models import UserProfile
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import UserProfile
import re
from django.core.mail import send_mail
from django.conf import settings
from .models import OTP
import random
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
import random
import re
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.mail import send_mail, EmailMessage
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.conf import settings
from .models import UserProfile  # Assuming UserProfile stores mobile_number

def register(request):
    if request.method == 'POST':
        step = request.POST.get('step', '1')
        
        if step == '1':
            # Step 1: Input Validation
            username = request.POST.get('username')
            email = request.POST.get('email')
            mobile_number = request.POST.get('mobile_number')
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')

            request.session['reg_data'] = {
                'username': username,
                'email': email,
                'mobile_number': mobile_number,
                'password1': password1,
                'password2': password2,
            }

            is_valid = True

            if password1 != password2:
                messages.error(request, 'Passwords do not match.')
                is_valid = False
            elif len(password1) < 8 or not re.search(r'[A-Z]', password1) or not re.search(r'[a-z]', password1) or not re.search(r'[0-9]', password1):
                messages.error(request, 'Password must be 8+ characters and contain uppercase, lowercase, and number.')
                is_valid = False

            if len(username) < 4 or User.objects.filter(username=username).exists():
                messages.error(request, 'Invalid or existing username.')
                is_valid = False

            try:
                validate_email(email)
                if User.objects.filter(email=email).exists():
                    messages.error(request, 'Email already exists.')
                    is_valid = False
            except ValidationError:
                messages.error(request, 'Invalid email.')

            if not re.match(r'^\+?1?\d{9,15}$', mobile_number):
                messages.error(request, 'Invalid mobile number.')
                is_valid = False
            elif UserProfile.objects.filter(mobile_number=mobile_number).exists():
                messages.error(request, 'Mobile number already exists.')
                is_valid = False

            if not is_valid:
                return render(request, 'users/register.html', {
                    'username': username,
                    'email': email,
                    'mobile_number': mobile_number
                })

            # Send OTP
            otp = random.randint(100000, 999999)
            request.session['otp'] = str(otp)

            send_mail(
                subject='OTP Verification - Your Registration',
                message=f'Your OTP code is: {otp}',
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[email],
                fail_silently=False,
            )

            return render(request, 'users/otp_verify.html', {'email': email})

        elif step == '2':
            # Step 2: Verify OTP and create user
            input_otp = request.POST.get('otp')
            session_otp = request.session.get('otp')
            reg_data = request.session.get('reg_data')

            if input_otp == session_otp and reg_data:
                try:
                    user = User.objects.create_user(
                        username=reg_data['username'],
                        email=reg_data['email'],
                        password=reg_data['password1']
                    )
                    UserProfile.objects.create(user=user, mobile_number=reg_data['mobile_number'])

                    # Clear session
                    del request.session['otp']
                    del request.session['reg_data']

                    messages.success(request, 'Account created successfully. Please login.')
                    return redirect('login')
                except Exception as e:
                    messages.error(request, f'Error: {e}')
            else:
                messages.error(request, 'Invalid OTP')

            return render(request, 'users/otp_verify.html', {'email': reg_data['email']})
    
    return render(request, 'users/register.html')


from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.models import User

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Check if the username exists
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, 'Username is not valid.')
            return redirect('login')
        
        # Try to authenticate the user
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            # messages.success(request, f'You have successfully logged in with username: {username}')
            return redirect('home')
        else:
            # If authentication fails, check password validity
            messages.error(request, 'Password is not valid.')
            return redirect('login')

    return render(request, 'users/login.html')


def project_category(request):
    return render(request, "users/project_categories.html")

def all_mini(request):
    return render(request, "users/all_mini_projects.html")

@login_required
def profile(request):
    return render(request, 'users/profile.html', {'user': request.user})

def logout_view(request):
    logout(request)
    return redirect('login')


def is_admin(user):
    return user.is_staff  # Allows access only to admin/staff users

def add_project(request):
    if request.method == 'POST':
        project_name = request.POST.get('project_name')
        project_pdf = request.FILES.get('project_pdf')
        project_zip = request.FILES.get('project_zip')
        amount = request.POST.get('amount')
        category = request.POST.get('category')
        project_type = request.POST.get('project_type')  # New field

        project = Project(
            project_name=project_name,
            project_pdf=project_pdf,
            project_zip=project_zip,
            amount=amount,
            category=category,
            project_type=project_type  # New field
        )
        project.save()
        messages.success(request, 'Project added successfully.')

    return render(request, 'admin/add_project.html')


def project_list(request):
    projects = Project.objects.all()
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)


    return render(request, 'users/project_list.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })


from django.shortcuts import render
from .models import Project

def ml_projects(request):
    projects = Project.objects.filter(category='ML', project_type='Major Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/ml_projects.html', {'projects': projects,'purchased_projects': purchased_projects})

def ml_mini_projects(request):
    projects = Project.objects.filter(category='ML', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/ml_mini_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def aws_projects(request):
    projects = Project.objects.filter(category='AWS', project_type='Major Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/aws_projects.html', {'projects': projects,'purchased_projects': purchased_projects})

def aws_mini_projects(request):
    projects = Project.objects.filter(category='AWS', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/aws_mini_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def react_projects(request):
    projects = Project.objects.filter(category='React', project_type='Major Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/react_projects.html', {'projects': projects,'purchased_projects': purchased_projects})

def react_mini_projects(request):
    projects = Project.objects.filter(category='React', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/react_mini_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def flask_projects(request):
    projects = Project.objects.filter(category='Flask', project_type='Major Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/flask_projects.html', {'projects': projects,'purchased_projects': purchased_projects})

def flask_mini_projects(request):
    projects = Project.objects.filter(category='Flask', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/flask_mini_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def python_projects(request):
    projects = Project.objects.filter(category='Python', project_type='Major Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/python_projects.html', {'projects': projects,'purchased_projects': purchased_projects})

def python_mini_projects(request):
    projects = Project.objects.filter(category='Python', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/python_mini_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def django_projects(request):
    projects = Project.objects.filter(category='Django', project_type='Major Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/django_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def django_mini_projects(request):
    projects = Project.objects.filter(category='Django', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/django_mini_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def php_projects(request):
    projects = Project.objects.filter(category='PHP', project_type='Major Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/php_projects.html', {'projects': projects,'purchased_projects': purchased_projects})

def php_mini_projects(request):
    projects = Project.objects.filter(category='PHP', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/php_mini_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def azure_projects(request):
    projects = Project.objects.filter(category='Azure', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/azure_projects.html', {'projects': projects,'purchased_projects': purchased_projects})

def azure_mini_projects(request):
    projects = Project.objects.filter(category='Azure', project_type='Mini Project')
    purchased_projects = ProjectPurchase.objects.filter(user=request.user, purchased=True).values_list('project_id', flat=True)
    return render(request, 'users/azure_mini_projects.html', {
        'projects': projects,
        'purchased_projects': purchased_projects
    })

def initiate_payment(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    return redirect('project_list',{'project':project})


import razorpay
from django.conf import settings
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_exempt
from .models import Project, ProjectPurchase
from django.contrib import messages

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

def initiate_payment(request, project_id):
    project = get_object_or_404(Project, serial_number=project_id)

    # Create Razorpay order
    order_amount = int(project.amount * 100)
    order_currency = 'INR'
    order_receipt = f'order_rcptid_{project_id}'

    # Razorpay order creation
    razorpay_order = razorpay_client.order.create({
        "amount": order_amount,
        "currency": order_currency,
        "receipt": order_receipt,
        "payment_capture": "1"
    })

    # Save order details in ProjectPurchase model
    purchase = ProjectPurchase.objects.create(
        user=request.user,
        project=project,
        order_id=razorpay_order['id']
    )

    return render(request, 'users/payment_page.html', {
        'project': project,
        'razorpay_order_id': razorpay_order['id'],
        'razorpay_key_id': settings.RAZORPAY_KEY_ID,
        'order_amount': order_amount
    })


from django.core.paginator import Paginator

@login_required
def my_orders(request):
    purchases_list = ProjectPurchase.objects.filter(
        user=request.user,
        purchased=True
    ).select_related('project').order_by('-created_at')
    
    paginator = Paginator(purchases_list, 10)  # Show 10 orders per page
    page_number = request.GET.get('page')
    purchases = paginator.get_page(page_number)
    
    return render(request, 'users/my_orders.html', {'purchases': purchases})


@csrf_exempt
def payment_success(request):
    if request.method == "POST":
        razorpay_payment_id = request.POST.get('razorpay_payment_id')
        order_id = request.POST.get('order_id')

        try:
            purchase = ProjectPurchase.objects.get(order_id=order_id)
            purchase.razorpay_payment_id = razorpay_payment_id
            purchase.purchased = True
            purchase.save()
            messages.success(request, 'Payment was successful.')

            return redirect('my_orders')
        except ProjectPurchase.DoesNotExist:
            messages.error(request, 'Payment verification failed.')
            return redirect('allprojects')


@login_required
def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')  # Retrieve mobile number
        message = request.POST.get('message')

        # Save the feedback to the database
        feedback = Contact(name=name, email=email, mobile=mobile, message=message)
        feedback.save()

    return render(request, "users/contact.html")

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Project

def remove_project(request):
    if request.method == 'POST':
        serial_number = request.POST.get('serial_number')

        try:
            # Find the project with the given serial number
            project = Project.objects.get(serial_number=serial_number)
            project.delete()  # Delete the project from the database
            messages.success(request, f'Project with serial number {serial_number} has been removed successfully.')
        except Project.DoesNotExist:
            messages.error(request, f'No project found with serial number {serial_number}.')

        return redirect('remove_project')  # Redirect back to the remove project page

    return render(request, 'admin/remove_project.html')

@login_required
def home(request):
    return render(request,"users/home.html")


def allprojects(request):
    return render(request,"users/allprojects.html")

@login_required
def about(request):
    return render(request,"users/about.html")

def callback(request):
    call=Contact.objects.all()
    return render(request,"admin/callback.html",{'call':call})

def admindashboard(request):
    return render(request,"admin/admin_dashboard.html")

@login_required
def feedback_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        feedback_text = request.POST.get('feedback')

        # Save feedback in the database
        feedback = Feedback(name=name, email=email, feedback=feedback_text)
        feedback.save()
        
        messages.success(request, 'Thank you for your feedback!')
        return redirect('feedback')  # Redirect back to feedback page

    return render(request, 'users/feedback.html')

def projects(request):
    all_projects = Project.objects.all()
    return render(request, 'admin/projects.html', {'all_projects': all_projects})

def edit_project(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    if request.method == 'POST':
        project.project_name = request.POST.get('project_name')
        if 'project_pdf' in request.FILES:
            project.project_pdf = request.FILES.get('project_pdf')
        if 'project_zip' in request.FILES:
            project.project_zip = request.FILES.get('project_zip')
        project.amount = request.POST.get('amount')
        project.category = request.POST.get('category')
        project.save()
        messages.success(request, 'Project updated successfully.')
        return redirect('projects')

    return render(request, 'admin/edit_project.html', {'project': project})

def delete_project(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    project.delete()
    messages.success(request, 'Project deleted successfully.')
    return redirect('projects')

def adminfeed(request):
    feed=Feedback.objects.all()
    return render(request, 'admin/adminfeedback.html',{'feed':feed})

def userdetails(request):
    users = User.objects.all().select_related('userprofile')
    return render(request, 'admin/user_details.html',{'user':users})


# views.py

from django.shortcuts import render, redirect
from django.contrib import messages

def admin_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Hardcoded credentials
        admin_username = "admin"
        admin_password = "admin"

        if username == admin_username and password == admin_password:
            # Redirect to the admin dashboard
            return redirect('/admindashboard/')
        else:
            # Display an error message
            messages.error(request, "Invalid username or password.")
            return redirect('admin_login')  # Redirect back to the login page with an error message

    return render(request, 'admin/admin_login.html')
 
def sorry(request):
    return render(request, 'users/sorry.html')




def purchase_details_view(request):
    # Add filter for purchased=True
    purchases_list = ProjectPurchase.objects.select_related('user', 'project')\
                              .filter(purchased=True)\
                              .order_by('-created_at')
    paginator = Paginator(purchases_list, 20)  # 20 orders per page

    page_number = request.GET.get('page')
    purchases = paginator.get_page(page_number)  # This returns the page object

    return render(request, 'admin/purchase_details.html', {'purchases': purchases})



from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages

# Step 1: Email verification for password reset
def password_reset_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        
        if user:
            # Email exists: redirect to password reset form
            request.session['reset_user_id'] = user.id  # Save user ID in session
            return redirect('password_reset_form')
        else:
            messages.error(request, 'The email is not registered. Please try again.')

    return render(request, 'users/password_reset_request.html')

# Step 2: Form to reset password
def password_reset_form(request):
    if 'reset_user_id' not in request.session:
        return redirect('password_reset_request')  # Ensure the flow is valid

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, 'Passwords do not match. Please try again.')
        else:
            user_id = request.session.pop('reset_user_id')  # Retrieve and remove user ID from session
            user = User.objects.get(id=user_id)
            user.set_password(new_password)  # Update password
            user.save()
            messages.success(request, 'Your password has been reset successfully.')
            return redirect('login')

    return render(request, 'users/password_reset_form.html')


import random
import logging
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.db import models

# Set up logging
logger = logging.getLogger(__name__)

def generate_otp():
    return str(random.randint(100000, 999999))

def forgot_password(request):
    print("=== FORGOT PASSWORD DEBUG START ===")
    
    if request.method == 'POST':
        email = request.POST.get('email')
        print(f"1. Email received: {email}")
        
        if not email:
            print("ERROR: No email provided")
            messages.error(request, 'Email is required')
            return render(request, 'users/forgot_password.html')
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
            print(f"2. User found: {user.username} ({user.email})")
        except User.DoesNotExist:
            print(f"ERROR: No user found with email: {email}")
            messages.error(request, f'No user found with email: {email}')
            return render(request, 'users/forgot_password.html')
        
        # Generate OTP
        otp_code = generate_otp()
        print(f"3. Generated OTP: {otp_code}")
        
        # Save OTP to database
        try:
            # Mark existing OTPs as used
            old_otps = OTP.objects.filter(user=user, is_used=False)
            print(f"4. Found {old_otps.count()} unused OTPs, marking as used")
            old_otps.update(is_used=True)
            
            # Create new OTP
            otp_record = OTP.objects.create(user=user, otp=otp_code)
            print(f"5. OTP saved to database: ID {otp_record.id}")
        except Exception as e:
            print(f"ERROR: Failed to save OTP: {e}")
            messages.error(request, 'Database error occurred')
            return render(request, 'users/forgot_password.html')
        
        # Test email settings first
        print("6. Testing email configuration...")
        print(f"   EMAIL_HOST: {getattr(settings, 'EMAIL_HOST', 'NOT SET')}")
        print(f"   EMAIL_PORT: {getattr(settings, 'EMAIL_PORT', 'NOT SET')}")
        print(f"   EMAIL_HOST_USER: {getattr(settings, 'EMAIL_HOST_USER', 'NOT SET')}")
        print(f"   EMAIL_USE_TLS: {getattr(settings, 'EMAIL_USE_TLS', 'NOT SET')}")
        print(f"   DEFAULT_FROM_EMAIL: {getattr(settings, 'DEFAULT_FROM_EMAIL', 'NOT SET')}")
        
        # Send email
        try:
            print("7. Attempting to send email...")
            
            email_subject = 'Password Reset OTP - Test'
            email_message = f'''Hello {user.username},

Your OTP for password reset is: {otp_code}

This OTP is valid for 15 minutes.

This is a test email.'''
            
            print(f"   Subject: {email_subject}")
            print(f"   To: {email}")
            print(f"   From: {settings.DEFAULT_FROM_EMAIL}")
            
            # Import here to avoid circular imports
            from django.core.mail import send_mail
            
            result = send_mail(
                email_subject,
                email_message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            print(f"8. Email send result: {result}")
            
            if result == 1:
                print("SUCCESS: Email sent successfully!")
                request.session['reset_user_email'] = email
                messages.success(request, f'OTP has been sent to {email}. Check your inbox and spam folder.')
                return redirect('verify_otp')
            else:
                print("WARNING: send_mail returned 0 - email may not have been sent")
                messages.error(request, 'Email sending failed - no error but result was 0')
                
        except Exception as e:
            print(f"ERROR: Email sending failed: {type(e).__name__}: {str(e)}")
            
            # Check specific error types
            error_str = str(e).lower()
            if 'authentication failed' in error_str:
                messages.error(request, 'Gmail authentication failed. Check your app password.')
            elif 'connection' in error_str or 'timeout' in error_str:
                messages.error(request, 'Cannot connect to Gmail servers. Check internet connection.')
            elif 'recipient' in error_str or 'address' in error_str:
                messages.error(request, 'Invalid email address format.')
            else:
                messages.error(request, f'Email error: {str(e)}')
            
            return render(request, 'users/forgot_password.html')
    
    print("=== FORGOT PASSWORD DEBUG END ===")
    return render(request, 'users/forgot_password.html')

def verify_otp(request):
    email = request.session.get('reset_user_email')
    if not email:
        messages.error(request, 'Session expired. Please request a new OTP.')
        return redirect('forgot_password')
    
    if request.method == 'POST':
        otp_entered = request.POST.get('otp')
        if not otp_entered:
            messages.error(request, 'Please enter the OTP')
            return render(request, 'users/verify_otp.html', {'email': email})
            
        try:
            user = User.objects.get(email=email)
            otp_record = OTP.objects.filter(user=user, is_used=False).latest('created_at')
            
            if otp_record.otp == otp_entered and otp_record.is_valid():
                otp_record.mark_as_used()
                request.session['otp_verified'] = True
                messages.success(request, 'OTP verified successfully!')
                return redirect('reset_password')
            else:
                messages.error(request, 'Invalid or expired OTP. Please try again.')
                
        except (User.DoesNotExist, OTP.DoesNotExist):
            messages.error(request, 'Invalid request. Please start over.')
            return redirect('forgot_password')
    
    return render(request, 'users/verify_otp.html', {'email': email})

def reset_password(request):
    email = request.session.get('reset_user_email')
    otp_verified = request.session.get('otp_verified')
    
    if not email or not otp_verified:
        return redirect('forgot_password')
    
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        if password != confirm_password:
            messages.error(request, 'Passwords do not match')
            return render(request, 'users/reset_password.html')
        
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            
            # Clear session variables
            del request.session['reset_user_email']
            del request.session['otp_verified']
            
            # Update session if user is logged in
            update_session_auth_hash(request, user)
            
            messages.success(request, 'Password reset successfully. You can now login with your new password.')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'User not found')
            return redirect('forgot_password')
    
    return render(request, 'users/reset_password.html')
def get_bot_response(user_input):
    lower_input = user_input.lower()
    for key in CHATBOT_RESPONSES:
        if key in lower_input:
            return CHATBOT_RESPONSES[key]
    return CHATBOT_RESPONSES["default"]


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
import json
from .models import ChatMessage

@csrf_exempt
@login_required
def chatbot_api(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_message = data.get("message", "").strip()
            bot_reply = get_bot_response(user_message)

            # Save chat to DB
            ChatMessage.objects.create(
                user=request.user,
                user_input=user_message,
                bot_response=bot_reply
            )

            return JsonResponse({"response": bot_reply})
        except Exception as e:
            return JsonResponse({"error": str(e)})
    else:
        return JsonResponse({"error": "Only POST method is allowed"})


from django.core.paginator import Paginator

def chatbot_page(request):
    selected_user_id = request.GET.get('user')
    messages = ChatMessage.objects.all().order_by('-timestamp')

    if selected_user_id:
        messages = messages.filter(user__id=selected_user_id)

    paginator = Paginator(messages, 5)  # Show 5 messages per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    users = User.objects.all()

    return render(request, "chat_history.html", {
        "messages": page_obj,
        "users": users,
        "selected_user_id": selected_user_id,
        "page_obj": page_obj
    })


CHATBOT_RESPONSES = {
    # Greetings
    "hi": "Hello! How can I help you with academic projects?",
    "hello": "Hi there! Ask me anything about project downloads or payments.",
    "hey": "Hey! How can I assist you today?",
    "morning": "Good morning! How can I help you with your projects?",
    "afternoon": "Good afternoon! What academic project info do you need?",
    "evening": "Good evening! Feel free to ask about project purchases.",
    "who": "I'm just a bot, but I'm here to help!",
     "see": "You can see project details, pricing, and documentation on each project's page.",
    "how": "I'm just a bot, but I'm here to help you with your project queries!",
    "what": "I'm your academic project assistant bot. Ask me anything!",
    "thank": "You're welcome! Let me know if you have more questions.",
    "bye": "Goodbye! Have a great day.",
    "night": "Good night! Reach out whenever you need project assistance.",
    
    # Payment related
    "payment": "We use Razorpay for payments. Once paid, you can download the project zip.",
    "pay": "You can pay securely using Razorpay through our payment gateway.",
    "methods": "We accept payments via Razorpay using debit cards, credit cards, and UPI.",
    "refund": "Refunds are subject to our policy. Contact us for details.",
    "confirmation": "You will receive a confirmation email after successful payment.",
    "issues": "For any payment issues, contact us via the Contact Us page.",
    
    # Download related
    "download": "Download is available only after payment is successful.",
    "link": "You can find your project download link in the Orders section after payment.",
    "failed": "If download fails, try again or contact support for help.",
    "format": "Projects are downloaded as zip files containing source code and documentation.",
    "buy": "You can buy projects securely via Razorpay. After payment, download links will be available.",
    "zip": "Each project zip file contains the full source code and detailed documentation.",
    
    # Project details
    "project": "We offer projects in Python, Django, ML, AI, DL, Azure, AWS, PHP, Flask, React, and more.",
    "price": "Project prices vary by category and complexity. Check project details for exact prices.",
    "documentation": "Yes, every project comes with complete documentation to help you run it.",
    "original": "Yes, all projects are original and carefully prepared by experts.",
    "customize": "Yes, you can customize the source code as needed after purchase.",
    "support": "Support is available for payment and download issues, but not for project modifications.",
    
    # User account related
    "password": "Click on 'Forgot Password' to reset using OTP sent to your email.",
    "login": "If you can't login, try resetting your password or contact support.",
    "register": "Click the Sign Up button and fill the registration form to create an account.",
    "account": "Account is verified via email OTP during registration.",
    "logout": "Click the logout button in the navigation bar to safely sign out.",
    
    # Orders and feedback
    "orders": "Your orders page lists all your purchased projects and payment details.",
    "feedback": "We value your feedback! Use the Feedback page to share your experience.",
    "contact": "Use the Contact Us page to reach our support team for any queries.",
    "cancel": "Digital project purchases cannot be canceled once payment is done.",
    
    # Personal/chat style
    "name": "I'm LMS Assistant Bot.",
    "human": "I'm a bot here to help you 24/7!",
    "joke": "Why do programmers prefer dark mode? Because light attracts bugs!",
    "help": "Sure! Please ask your question related to academic projects or payments.",
    
    # Technical questions
    "razorpay": "We use Razorpay as our trusted payment gateway.",
    "demo": "We don't provide demo videos before payment, but you can download the project document without payment.",
    "run": "Follow the documentation included in the project zip to run your project successfully.",
    
    # Miscellaneous
    "contact": "Use the Contact Us page to send us your queries or feedback.",
    "share": "No, sharing purchased projects violates our terms.",
    "discount": "Occasionally, we offer discounts. Check our homepage for updates.",
    "languages": "We offer projects in Python, Django, PHP, React, ML, AI, and more.",
    
    # Fallback
    "default": "Sorry, I didn't get that. You can ask about relevant things on this website.",
}





def chatbot_history(request):
    selected_user_id = request.GET.get("user")

    if selected_user_id:
        messages_list = ChatMessage.objects.filter(user_id=selected_user_id).order_by('-timestamp')
    else:
        messages_list = ChatMessage.objects.all().order_by('-timestamp')

    paginator = Paginator(messages_list, 10)  # 10 messages per page

    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    users = User.objects.all()

    return render(request, "admin/chat_history.html", {
        "page_obj": page_obj,
        "users": users,
        "selected_user_id": selected_user_id
    })

def statistics(request):
    return render(request,"admin/statistics.html")

# views.py
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse

# views.py
from django.views.decorators.csrf import csrf_exempt
from django.core.serializers import serialize
import json

@csrf_exempt
def user_statistics(request):
    try:
        today = timezone.now().date()
        total = User.objects.count()
        
        data = {
            'total_users': total,
            'new_users_today': User.objects.filter(date_joined__date=today).count(),
            'active_users': User.objects.filter(last_login__gte=timezone.now()-timedelta(days=30)).count(),
            'growth_rate': 5.2  # Example static value - replace with your calculation
        }
        return JsonResponse(data, status=200)
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def calculate_growth_rate():
    today = timezone.now().date()
    last_week = today - timedelta(days=7)
    
    current_count = User.objects.count()
    previous_count = User.objects.filter(date_joined__lt=last_week).count()
    
    if previous_count == 0:
        return 0
    
    growth_rate = ((current_count - previous_count) / previous_count) * 100
    return round(growth_rate, 1)


from django.http import JsonResponse
from .models import Project, ProjectPurchase

def project_statistics(request):
    total_projects = Project.objects.count()

    # Get distinct project IDs from paid purchases
    paid_project_ids = ProjectPurchase.objects.filter(paid=True).values_list('project__serial_number', flat=True).distinct()

    # Count only those projects
    paid_projects = Project.objects.filter(serial_number__in=paid_project_ids).count()

    return JsonResponse({
        'total_projects': total_projects,
        'paid_projects': paid_projects,
    })
