from django.db import models
from django.contrib.auth.models import User

from django.core.validators import RegexValidator

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mobile_number = models.CharField(
        max_length=15,
        validators=[
            RegexValidator(
                regex=r'^\+?1?\d{9,15}$',
                message="Phone number must be entered in the format: '+999999999'. Only 10 digits allowed."
            )
        ]
    )

class Project(models.Model):
    CATEGORY_CHOICES = [
        ('ML', 'ML'),
        ('Python', 'Python'),
        ('Django', 'Django'),
        ('PHP', 'PHP'),
        ('Azure', 'Azure'),
        ('AWS', 'AWS'),          
        ('Flask', 'Flask'),      
        ('React', 'React'),      
    ]

    PROJECT_TYPE_CHOICES = [
    ('Mini Project', 'Mini Project'),
    ('Major Project', 'Major Project'),
]

    serial_number = models.AutoField(primary_key=True)
    project_name = models.CharField(max_length=200)
    project_pdf = models.FileField(upload_to='project_pdfs/')
    project_zip = models.FileField(upload_to='project_zips/')
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    category = models.CharField(max_length=20, null=True, blank=True, choices=CATEGORY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True,)
    project_type = models.CharField(max_length=20,choices=PROJECT_TYPE_CHOICES,null=True,blank=True)
    def __str__(self):
        return self.project_name

class ProjectPurchase(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    purchased = models.BooleanField(default=False)
    order_id = models.CharField(max_length=100, blank=True, null=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True, null=True)
    paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    mobile = models.CharField(max_length=15,null=True,blank=True)  # Added mobile number field
    message = models.TextField()


class Feedback(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    feedback = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)

    def __str__(self):
        return f"{self.name} - {self.email}"
    

# users/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def is_valid(self):
        return not self.is_used and timezone.now() < self.created_at + timedelta(minutes=15)
    
    def mark_as_used(self):
        self.is_used = True
        self.save()

    def __str__(self):
        return f"OTP for {self.user.username} - {self.otp}"

    class Meta:
        ordering = ['-created_at']



from django.db import models
from django.contrib.auth.models import User

class ChatMessage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user_input = models.TextField()
    bot_response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.user_input[:30]}"
