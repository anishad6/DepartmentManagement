from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings


class Department(models.Model):
    dept_id = models.AutoField(primary_key=True)  
    name = models.CharField(max_length=100, verbose_name="Department Name")  
    description = models.TextField(max_length=500, blank=True, verbose_name="Description") 
    created_at = models.DateTimeField(auto_now_add=True)  
    updated_at = models.DateTimeField(auto_now=True) 
    status = models.BooleanField(default=True, verbose_name="Is Active")  

    class Meta:
        verbose_name = "Department"
        verbose_name_plural = "Departments"
        ordering = ['-created_at']  # Newest first

    def __str__(self):
        return self.name


class Role(models.Model):
    role_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    status = models.BooleanField(default=True)  # True = Active, False = Inactive
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class EmployeeManager(BaseUserManager):
    def create_employee(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        employee = self.model(username=username, email=email, **extra_fields)
        employee.set_password(password)
        employee.save(using=self._db)
        return employee

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_employee(username, email, password, **extra_fields)


class Employee(AbstractBaseUser, PermissionsMixin):
    employee_id = models.AutoField(primary_key=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField()
    mobile = models.CharField(max_length=15)
    dept = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True)
    role = models.ForeignKey('Role', on_delete=models.SET_NULL, null=True)
    reporting_manager = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name="employees")
    date_of_joining = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_staff = models.BooleanField(default=False)

    objects = EmployeeManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


    
class PasswordResetOTP(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        from datetime import timedelta, timezone
        return self.created_at >= timezone.now() - timedelta(minutes=10)
    

class Task(models.Model):
    task_id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=200)
    description = models.TextField()
    priority = models.CharField(max_length=10, choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')])
    task_type = models.CharField(max_length=20, choices=[('Individual', 'Individual'), ('Team', 'Team')])
    assigned_to = models.ForeignKey('Employee', on_delete=models.CASCADE, related_name='tasks')
    created_by = models.ForeignKey('Employee', on_delete=models.CASCADE, related_name='created_tasks')
    start_date = models.DateField()
    end_date = models.DateField()
    status = models.CharField(
        max_length=20, 
        choices=[('Pending', 'Pending'), ('In Progress', 'In Progress'), ('Completed', 'Completed')], 
        default='Pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class TaskAssignment(models.Model):
    assignment_id = models.AutoField(primary_key=True)
    task = models.ForeignKey('Task', on_delete=models.CASCADE, related_name='assignments')
    employee = models.ForeignKey('Employee', on_delete=models.CASCADE, related_name='assigned_tasks')  # Assigned to
    assigned_by = models.ForeignKey('Employee', on_delete=models.CASCADE, related_name='tasks_assigned')  # Assigned by
    assigned_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=200,
        choices=[('Pending', 'Pending'), ('In Progress', 'In Progress'), ('Completed', 'Completed')],
        default='Pending'
    )
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Assignment {self.assignment_id} - Task {self.task.title}"


class Review(models.Model):
    review_id = models.AutoField(primary_key=True)  # Unique identification of the review
    review_title = models.CharField(max_length=100)  # Title or small details of the review
    review_date = models.DateField()  # Date on which the review is taken
    employee = models.ForeignKey('Employee', on_delete=models.CASCADE, related_name='reviews')  # Reference to employee reviewed
    reviewed_by = models.ForeignKey('Employee', on_delete=models.CASCADE, related_name='reviews_given')  # Reference to reviewer
    review_period = models.CharField(max_length=100, choices=[('Monthly', 'Monthly'), ('Quarterly', 'Quarterly'), ('Annually', 'Annually')])  # Review period
    rating = models.IntegerField()  # Rating given to employee between 1-10
    comments = models.CharField(max_length=300, blank=True, null=True)  # Extra comments by reviewer
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when review was first created
    updated_at = models.DateTimeField(auto_now=True)  # Timestamp when review was last updated

    def __str__(self):
        return f"Review {self.review_id} for {self.employee.username}"


class Leave(models.Model):
    class LeaveType(models.TextChoices):
        SICK_LEAVE = 'SL', 'Sick Leave'
        CASUAL_LEAVE = 'CL', 'Casual Leave'
        PRIVILEGE_LEAVE = 'PL', 'Privilege Leave'
        LEAVE_WITHOUT_PAY = 'LWP', 'Leave Without Pay'

    class Status(models.TextChoices):
        APPROVED = 'approved', 'Approved'
        REJECTED = 'rejected', 'Rejected'
        PENDING = 'pending', 'Pending'

    leave_id = models.AutoField(primary_key=True)
    employee = models.ForeignKey('Employee', on_delete=models.CASCADE, related_name='leaves')
    leave_type = models.CharField(max_length=3, choices=LeaveType.choices)
    reason = models.CharField(max_length=200)
    start_date = models.DateField()
    end_date = models.DateField()
    total_days = models.PositiveIntegerField()
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    approved_by = models.ForeignKey('Employee', on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_leaves')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Leave {self.leave_id} ({self.leave_type}) for Employee {self.employee.username}"

class LeaveQuota(models.Model):
    class LeaveType(models.TextChoices):
        SICK_LEAVE = 'SL', 'Sick Leave'
        CASUAL_LEAVE = 'CL', 'Casual Leave'
        PRIVILEGE_LEAVE = 'PL', 'Privilege Leave'
        LEAVE_WITHOUT_PAY = 'LWP', 'Leave Without Pay'

    quota_id = models.AutoField(primary_key=True)
    employee = models.ForeignKey('Employee', on_delete=models.CASCADE, related_name='leave_quotas')
    leave_type = models.CharField(max_length=3, choices=LeaveType.choices)
    total_quota = models.PositiveIntegerField()
    used_quota = models.PositiveIntegerField(default=0)
    remain_quota = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.remain_quota = self.total_quota - self.used_quota
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Quota {self.quota_id} for Employee {self.employee.username} ({self.leave_type})"