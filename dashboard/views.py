
from django.shortcuts import render,redirect ,HttpResponse,get_object_or_404

from dashboard.models import Department,Role , Employee,PasswordResetOTP,Task,TaskAssignment,Review,Leave,LeaveQuota
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout, get_user_model
from django.contrib import messages
from django.core.mail import send_mail
import string
import random
from django.conf import settings
from django.contrib.auth.hashers import make_password  # Add this import if not already present

from django.db.models import Q
from datetime import datetime
from django.core.paginator import Paginator
from django.http import JsonResponse

from django.db.models import Count
from django.contrib.auth.decorators import login_required
from django.db.models import F
from collections import defaultdict
from django.http import HttpResponseForbidden
from collections import Counter








def is_admin(user):
    """
    Check if the given user has the role of 'Admin'.
    """
    try:
        # Debugging log to check the user's role
        print(f"User role: {user.role.name}")  
        
        # Check if the user's role is 'Admin'
        return user.role.name.lower() == 'admin'  # Case-insensitive comparison
    except AttributeError:
        # Log the error and return False if the user doesn't have a role or role_name
        print("Error: User does not have a valid role or role_name.")
        return False



# Create your views here.
def dashboard(request):
    # Filter departments with status=True directly
    data = Department.objects.filter(status=True)
    context = {}
    context['Departments'] = data
    return render(request, 'dashboard/home_dash.html', context)

   

# Create department (only for admins)
def create_department(request):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')

    elif request.method == 'GET':
        return render(request, 'dashboard/create_department.html')
    elif request.method == 'POST':
        department_name = request.POST["Department"]  
        description = request.POST["description"]   
        department = Department.objects.create(name=department_name, description=description)
        department.save()
        return redirect('/')

# Delete department (only for admins)
def delete_department(request, deptid):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')


    try:
        # Retrieve the specific department using the primary key
        department = Department.objects.get(dept_id=deptid)
    except Department.DoesNotExist:
        return HttpResponse("Department not found", status=404)

    # Mark department as inactive
    department.status = False
    department.save()

    return redirect('/')

# Update department (only for admins)
def update_department(request, deptid):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')


    try:
        # Retrieve the specific department using the primary key
        department = Department.objects.get(dept_id=deptid)
    except Department.DoesNotExist:
        return HttpResponse("Department not found", status=404)

    if request.method == 'GET':
        context = {'Departments': department}
        return render(request, 'dashboard/update.html', context)

    elif request.method == 'POST':
        dept_name = request.POST['Department']
        description = request.POST['description']

        if not dept_name or not description:
            return HttpResponse("Both Department Name and Description are required.", status=400)
        
        # Update the department object
        department.name = dept_name
        department.description = description
        department.save()

        return redirect('/')


def viewDepartment(request):
    # Retrieve all departments from the database
    departments = Department.objects.filter(status=True)
    return render(request, 'dashboard/department.html', {'departments': departments})



#  Role Dashboard
def role_dashboard(request):
    roles = Role.objects.filter(status=True)  # Only active roles
    return render(request, 'dashboard/view_role.html', {'role': roles})

# Create Role
def create_role(request):

    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')

    elif request.method == 'POST':
        name = request.POST['name']
        description = request.POST['description']

        if Role.objects.filter(name=name).exists():
            return HttpResponse("Role already exists!", status=400)

        Role.objects.create(name=name, description=description)
        return redirect('view_role')  # Use the name of the path from urls.py

    return render(request, 'dashboard/create_role.html')


# Update Role
def update_role(request, role_id):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')

    roles = Role.objects.get(role_id=role_id)

    if request.method == 'POST':
        name = request.POST['name']
        description = request.POST['description']

        if not name:
            return HttpResponse("Role name cannot be empty.", status=400)

        roles.name = name
        roles.description = description
        roles.save()
        return redirect('view_role')

    return render(request, 'dashboard/update_role.html', {'role': roles})

# Delete Role (Soft Delete)


def confirm_delete(request, role_id):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')

    # Use role_id instead of id to query the Role object
    role = get_object_or_404(Role, role_id=role_id)

    if request.method == 'POST':
        role.status = False  # Mark as inactive (soft delete)
        role.save()
        return redirect('view_role')  # Redirect to the role dashboard or appropriate page

    return render(request, 'dashboard/confirm_delete.html', {'role': role})




# Employee 

def employee_dashboard(request):
    employees =  Employee.objects.all()
    return render(request, 'dashboard/view_employee.html', {'employees': employees})

def create_employee(request):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')

    departments = Department.objects.all()
    roles = Role.objects.all()
    managers = Employee.objects.all()

    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')
        dept_id = request.POST.get('department')
        role_id = request.POST.get('role')
        reporting_manager_id = request.POST.get('reporting_manager')
        date_of_joining = request.POST.get('date_of_joining')

        department = Department.objects.get(dept_id=dept_id)
        role = Role.objects.get(role_id=role_id)
        reporting_manager = Employee.objects.get(employee_id=reporting_manager_id) if reporting_manager_id else None

        # Encrypt the password before saving
        encrypted_password = make_password(password)

        # Create the employee with the encrypted password
        Employee.objects.create(
            first_name=first_name,
            last_name=last_name,
            username=username,
            password=encrypted_password,  # Use encrypted password here
            email=email,
            mobile=mobile,
            dept=department,
            role=role,
            reporting_manager=reporting_manager,
            date_of_joining=date_of_joining
        )
        return redirect('view_employee')

    return render(request, 'dashboard/create_employee.html', {'departments': departments, 'roles': roles, 'managers': managers})
def update_employee(request, employee_id):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')

    employee = get_object_or_404( Employee, employee_id=employee_id)
    departments = Department.objects.all()
    roles = Role.objects.all()
    managers =  Employee.objects.exclude(employee_id=employee_id)

    if request.method == "POST":
        employee.first_name = request.POST.get('first_name')
        employee.last_name = request.POST.get('last_name')
        # employee.username = request.POST.get('username')
        # employee.password = request.POST.get('password')
        employee.email = request.POST.get('email')
        employee.mobile = request.POST.get('mobile')
        employee.dept = Department.objects.get(dept_id=request.POST.get('department'))
        employee.role = Role.objects.get(role_id=request.POST.get('role'))
        reporting_manager_id = request.POST.get('reporting_manager')
        employee.reporting_manager =  Employee.objects.get(employee_id=reporting_manager_id) if reporting_manager_id else None
        employee.date_of_joining = request.POST.get('date_of_joining')
        employee.save()
        return redirect('view_employee')

    return render(request, 'dashboard/update_employee.html', {
        'employee': employee,
        'departments': departments,
        'roles': roles,
        'managers': managers
    })




def confirm_delete(request, employee_id):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')

    # Use role_id instead of id to query the Role object
    employee = get_object_or_404(Employee, employee_id=employee_id)

    if request.method == 'POST':
        employee.status = False  # Mark as inactive (soft delete)
        employee.save()
        return redirect('view_employee')  # Redirect to the role dashboard or appropriate page

    return render(request, 'dashboard/employee_delete.html', {'employee': employee}) 




# User Login View
def userLogin(request):
    context = {}
    if request.method == "GET":
        return render(request, "dashboard/login.html", context)
    else:
        u = request.POST['username']  # Get the username
        p = request.POST['password']  # Get the password

        # Ensure the user model is correctly used for authentication
        User = get_user_model()

        # Authenticate the user using the custom model
        user = authenticate(request, username=u, password=p)

        if user is None:
            try:
                # Check if user exists by username
                employee = User.objects.get(username=u)
                context["error"] = "Invalid password"
            except User.DoesNotExist:
                context["error"] = "Invalid username"
            return render(request, "dashboard/login.html", context)
        else:
            if user.is_active:
                login(request, user)
                messages.success(request, "Logged in successfully!")
                return redirect("/")  # Redirect to the home page or another URL
            else:
                context["error"] = "User account is inactive"
                return render(request, "dashboard/login.html", context)



def userLogout(request):
    """
    Logs out the user and redirects to the homepage with a success message.
    """
    if request.user.is_authenticated:
        logout(request)
        messages.success(request, "Logged out successfully!")
    else:
        messages.warning(request, "You are not logged in.")

    return redirect("/")


def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")
        
        # Use the custom Employee model here instead of the default User model
        employees = Employee.objects.filter(email=email)

        if not employees.exists():
            messages.error(request, "No account found with that email.")
            return render(request, "dashboard/forgot_password.html")

        for employee in employees:
            # Generate an OTP
            otp = ''.join(random.choices(string.digits, k=6))
            PasswordResetOTP.objects.update_or_create(user=employee, defaults={"otp": otp})

            # Send the OTP via email
            send_mail(
                "Password Reset OTP",
                f"Hello {employee.username},\n\nYour OTP for resetting the password is: {otp}.\n\nUse this to reset your password.",
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

        messages.success(request, "An OTP has been sent to your email.")
        return redirect('enter_otp')  # Redirect to the OTP entry page
    return render(request, "dashboard/forgot_password.html")

# Enter OTP Function
def enter_otp(request):
    if request.method == "POST":
        otp = request.POST.get("otp")

        try:
            reset_entry = PasswordResetOTP.objects.get(otp=otp)
            # Save the user employee_id in the session
            request.session['reset_user_id'] = reset_entry.user.employee_id
            return redirect('reset_password')
        except PasswordResetOTP.DoesNotExist:
            messages.error(request, "Invalid or expired OTP.")
            return render(request, "dashboard/enter_otp.html")

    return render(request, "dashboard/enter_otp.html")


# Reset Password Function


def reset_password(request):
    user_id = request.session.get('reset_user_id')

    if not user_id:
        messages.error(request, "Unauthorized access. Please restart the process.")
        return redirect('forgot_password')

    try:
        user = get_object_or_404(Employee, employee_id=user_id)

        if request.method == 'POST':
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            if password != confirm_password:
                messages.error(request, "Passwords do not match.")
            else:
                user.set_password(password)  # Securely hash the password
                user.save()
                del request.session['reset_user_id']  # Clear session
                messages.success(request, "Your password has been reset successfully. You can now log in.")
                return redirect('login')
    except Employee.DoesNotExist:
        messages.error(request, "Invalid user.")
        return redirect('forgot_password')

    return render(request, 'dashboard/reset_password.html')


# Task work 

def view_tasks(request):
    try:
        # Start with all tasks assigned to the reporting manager
        tasks = Task.objects.filter(assigned_to__reporting_manager=request.user)

        # Filter by employee (if selected)
        employee_id = request.GET.get('employee_filter')
        if employee_id and employee_id != "all":
            tasks = tasks.filter(assigned_to_id=employee_id)

        # Filter by status (if selected)
        status = request.GET.get('status', '').strip()
        if status:
            status_mapping = {
                'pending': 'Pending',
                'in_progress': 'In Progress',
                'completed': 'Completed',
            }
            db_status = status_mapping.get(status.lower())
            if db_status:
                tasks = tasks.filter(status__iexact=db_status)

        # Filter by date range (if selected)
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if start_date and end_date:
            # Parse the date strings into datetime.date objects
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

            tasks = tasks.filter(
                start_date__lte=end_date,  # Task start date before or on the end date
                end_date__gte=start_date   # Task end date after or on the start date
            )

        # Task statistics (counts)
        completed_count = tasks.filter(status='Completed').count()
        in_progress_count = tasks.filter(status='In Progress').count()
        pending_count = tasks.filter(status='Pending').count()

        # Paginate tasks
        paginator = Paginator(tasks, 10)  # Show 10 tasks per page
        page_number = request.GET.get('page')
        tasks_page = paginator.get_page(page_number)

        # Fetch employees for the filter dropdown
        employees = Employee.objects.filter(tasks__isnull=False).values('employee_id', 'first_name', 'last_name').distinct()

        # Pass tasks and task statistics to the template
        context = {
            'tasks': tasks,
            'completed_count': completed_count,
            'in_progress_count': in_progress_count,
            'pending_count': pending_count,
            'employees': employees,
            'tasks_page': tasks_page
        }

        return render(request, 'dashboard/view_task.html', context)

    except Exception as e:
        # Log the error (optional) and display a friendly error message
        print(f"Error in view_tasks: {e}")
        return redirect('/dashboard/login')
        # return HttpResponse("An error occurred while fetching tasks. Please try again later.", status=500)
# Add a task
def add_task(request):
    user = request.user if request.user.is_authenticated else None
    if not user or not is_admin(user):
        messages.error(request, 'You do not have permission to perform this action please login.')
        return redirect('/dashboard/login')
    
    try:
        if request.method == 'POST':
            # Extract form data
            title = request.POST['title']
            description = request.POST['description']
            priority = request.POST['priority']
            task_type = request.POST['task_type']
            start_date = request.POST['start_date']
            end_date = request.POST['end_date']

            # Get the assigned employee
            try:
                assigned_to = Employee.objects.get(employee_id=request.POST['assigned_to'])
            except Employee.DoesNotExist:
                assigned_to = None  # Handle the case where the employee doesn't exist

            # Create the task only if an employee is found
            if assigned_to:
                Task.objects.create(
                    title=title,
                    description=description,
                    priority=priority,
                    task_type=task_type,
                    start_date=start_date,
                    end_date=end_date,
                    assigned_to=assigned_to,
                    created_by=request.user
                )
                return redirect('view_task')
            else:
                # Log or handle the case where no employee is found
                print("Assigned employee not found.")

        # Fetch employees for the form dropdown
        employees = Employee.objects.filter(reporting_manager=request.user)

        if not employees.exists():
            print("No employees found for the current user.")
        else:
            print("Employees:", employees)

        return render(request, 'dashboard/create_tasks.html', {'employees': employees})

    except Exception as e:
        # Log the error and redirect to an error page or show a friendly message
        print(f"Error in add_task: {e}")
        return render(request, 'dashboard/create_tasks.html', {
            'employees': [],
            'error_message': "An error occurred while creating the task. Please try again later."
        })
# Edit a task
def edit_task(request, task_id):
    task = get_object_or_404(Task, task_id=task_id)
    if request.method == 'POST':
        task.title = request.POST['title']
        task.description = request.POST['description']
        task.priority = request.POST['priority']
        task.task_type = request.POST['task_type']
        task.start_date = request.POST['start_date']
        task.end_date = request.POST['end_date']
        task.status = request.POST['status']
        task.save()
        return redirect('view_task')
    employees = Employee.objects.filter(reporting_manager=request.user)
    return render(request, 'dashboard/update_task.html', {'task': task, 'employees': employees})

# Delete a task
def delete_task(request, task_id):
    task = get_object_or_404(Task, task_id=task_id)
    task.delete()
    return redirect('view_task')

def mark_completed(request, task_id):
    task = get_object_or_404(Task, task_id=task_id)  # Use task_id here
    task.status = 'Completed'
    task.save()
    return redirect('view_task')

def task_details(request, task_id):
    # Use task_id for fetching task details
    task = get_object_or_404(Task, task_id=task_id)

    context = {
        'task': task
    }
    
    return render(request, 'dashboard/task_details.html', context)


# Review Employees

def view_reviews(request):
    # Ensure the user is authenticated
    if not request.user.is_authenticated:
        return redirect('login')  # Redirect to the login page (adjust URL name as needed)

    # Fetch the user's role
    user_role = request.user.role.name if request.user.role else None

    # Check if the user has the required role (admin, team leader, or manager)
    allowed_roles = ['admin', 'team leader', 'manager','Admin', 'Team Leader', 'Manager','ADMIN', 'TEAM LEADER', 'MANAGER']
    
    if user_role not in allowed_roles:
        messages.error(request, "You do not have permission to view these reviews.")  # Add error message
        return redirect('/')  # Redirect to the home page with the error message

    # Extract query parameters for filtering
    department_filter = request.GET.get('department')
    employee_filter = request.GET.get('employee_filter')
    review_period = request.GET.get('review_period')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    rating_filter = request.GET.get('rating')
    search_employee = request.GET.get('search_employee')
    print(search_employee)
    print(employee_filter)
    # Start with the base query
    reviews = Review.objects.all()

    # Apply filters
    if department_filter:
        reviews = reviews.filter(employee__department__id=department_filter)
    if employee_filter:
        reviews = reviews.filter(employee__pk=employee_filter)
    if review_period:
        reviews = reviews.filter(review_period=review_period)
    if start_date and end_date:
        reviews = reviews.filter(review_date__range=[start_date, end_date])
    if rating_filter:
        if rating_filter == "1-5":
            reviews = reviews.filter(rating__range=(1, 5))
        elif rating_filter == "6-8":
            reviews = reviews.filter(rating__range=(6, 8))
        elif rating_filter == "9+":
            reviews = reviews.filter(rating__gte=9)
    if search_employee:
        reviews = reviews.filter(
            Q(employee__first_name__icontains=search_employee) |
            Q(employee__last_name__icontains=search_employee)
        )

    # Pagination
    paginator = Paginator(reviews, 10)
    page_number = request.GET.get('page')
    reviews_page = paginator.get_page(page_number)

    # Statistics for each period
    monthly_count = Review.objects.filter(review_period='Monthly').count()
    quarterly_count = Review.objects.filter(review_period='Quarterly').count()
    annual_count = Review.objects.filter(review_period='Annually').count()

    monthly_employees = Employee.objects.filter(reviews__review_period='Monthly').distinct().count()
    quarterly_employees = Employee.objects.filter(reviews__review_period='Quarterly').distinct().count()
    annual_employees = Employee.objects.filter(reviews__review_period='Annually').distinct().count()

    # Calculate number of reviews per rating range for each period
    monthly_range_1_5 = Review.objects.filter(review_period='Monthly', rating__range=(1, 5)).count()
    monthly_range_6_8 = Review.objects.filter(review_period='Monthly', rating__range=(6, 8)).count()
    monthly_range_9_plus = Review.objects.filter(review_period='Monthly', rating__gte=9).count()

    quarterly_range_1_5 = Review.objects.filter(review_period='Quarterly', rating__range=(1, 5)).count()
    quarterly_range_6_8 = Review.objects.filter(review_period='Quarterly', rating__range=(6, 8)).count()
    quarterly_range_9_plus = Review.objects.filter(review_period='Quarterly', rating__gte=9).count()

    annual_range_1_5 = Review.objects.filter(review_period='Annually', rating__range=(1, 5)).count()
    annual_range_6_8 = Review.objects.filter(review_period='Annually', rating__range=(6, 8)).count()
    annual_range_9_plus = Review.objects.filter(review_period='Annually', rating__gte=9).count()

    # Number of employees per rating range
    range_1_5_employees = Review.objects.filter(rating__range=(1, 5)).values('employee').distinct().count()
    range_6_8_employees = Review.objects.filter(rating__range=(6, 8)).values('employee').distinct().count()
    range_9_plus_employees = Review.objects.filter(rating__gte=9).values('employee').distinct().count()

    # Pass data to the template
    context = {
        'reviews_page': reviews_page,
        'departments': Department.objects.all(),
        'employees': Employee.objects.all(),
        'monthly_count': monthly_count,
        'quarterly_count': quarterly_count,
        'annual_count': annual_count,
        'monthly_employees': monthly_employees,
        'quarterly_employees': quarterly_employees,
        'annual_employees': annual_employees,
        'monthly_range_1_5': monthly_range_1_5,
        'monthly_range_6_8': monthly_range_6_8,
        'monthly_range_9_plus': monthly_range_9_plus,
        'quarterly_range_1_5': quarterly_range_1_5,
        'quarterly_range_6_8': quarterly_range_6_8,
        'quarterly_range_9_plus': quarterly_range_9_plus,
        'annual_range_1_5': annual_range_1_5,
        'annual_range_6_8': annual_range_6_8,
        'annual_range_9_plus': annual_range_9_plus,
        'range_1_5_employees': range_1_5_employees,
        'range_6_8_employees': range_6_8_employees,
        'range_9_plus_employees': range_9_plus_employees,
    }
    return render(request, 'dashboard/view_review.html', context)

def add_review(request):
    if request.method == 'POST':
        # Handle form submission and create a review
        employee_id = request.POST.get('employee_id')
        rating = request.POST.get('rating')
        review_period = request.POST.get('review_period')
        review_title = request.POST.get('review_title')
        comments = request.POST.get('comments')
        review_date = request.POST.get('review_date')

        # Ensure logged-in user is the reviewer
        reviewer = request.user

        # Create a new review object
        review = Review(
            employee_id=employee_id,
            rating=rating,
            review_period=review_period,
            review_title=review_title,
            comments=comments,
            review_date=review_date,
            reviewed_by=reviewer
        )
        review.save()

        return redirect('view_reviews')

    # Fetch employees to populate the dropdown
    employees = Employee.objects.all()
    review_periods = Review._meta.get_field('review_period').choices  # Monthly, Quarterly, Annually

    context = {
        'employees': employees,
        'review_periods': review_periods,
    }

    return render(request, 'dashboard/add_review.html', context)

def see_comments(request, review_id):
    # Fetch the review by its ID
    review = get_object_or_404(Review, review_id=review_id)

    # Pass the review (which already includes the comments field) to the context
    context = {
        'review': review
    }

    # Render the comments page with the review
    return render(request, 'dashboard/see_comment.html', context)


def edit_review(request, review_id):
    # Fetch the review to edit
    review = get_object_or_404(Review, review_id=review_id)
    
    # Fetch employees and review periods for dropdown options
    employees = Employee.objects.all()
    review_periods = Review._meta.get_field('review_period').choices
    
    # Create a list of ratings (1 to 10)
    ratings = list(range(1, 11))

    # If the form is submitted (POST request)
    if request.method == 'POST':
        # Get the data from the form
        employee_id = request.POST.get('employee_id')
        rating = request.POST.get('rating')
        review_period = request.POST.get('review_period')
        review_title = request.POST.get('review_title')
        comments = request.POST.get('comments')  # Get the updated comments
        review_date = request.POST.get('review_date')

        # Update the review with the new values
        review.employee_id = employee_id
        review.rating = rating
        review.review_period = review_period
        review.review_title = review_title
        review.comments = comments  # Update comments
        review.review_date = review_date

        # Save the updated review
        review.save()

        # Redirect to the review list with a success message
        messages.success(request, "Review updated successfully!")
        return redirect('view_reviews')

    # If the form is not submitted (GET request), render the edit form
    context = {
        'review': review,
        'employees': employees,
        'review_periods': review_periods,
        'ratings': ratings,  # Pass the ratings list to the template
    }
    return render(request, 'dashboard/edit_review.html', context)

def delete_review(request, review_id):
    # Fetch the review to delete by its ID
    review = get_object_or_404(Review, review_id=review_id)
    
    # Delete the review
    review.delete()
    
    # Display a success message
    messages.success(request, "Review deleted successfully!")
    
    # Redirect back to the review list
    return redirect('view_reviews')


# Leave management
@login_required
def leave_dashboard(request):
    # Ensure the user is authenticated
    if not request.user.is_authenticated:
        messages.error(request, 'You need to be logged in to access this page.')  # Add an error message
        return redirect('login')  # Redirect to login page if not authenticated

    # Check if the user has a valid role and handle redirection based on the role
    if request.user.role:  # Ensure the user has a role assigned
        user_role = request.user.role.name   # Assuming `role` is a ForeignKey to the `Roles` model

        if user_role == 'Admin':
            # Redirect to admin leave dashboard
            return redirect('leave_dashboard_admin')
        elif user_role == 'Employee':
            # Redirect to employee leave dashboard
            return redirect('leave_dashboard_employee')
        elif user_role == 'Team Leader' or user_role == 'Manager':
            # Redirect for team leaders or managers (if applicable)
            return redirect('leave_dashboard_admin')  # Example for team leaders/managers
        else:
            # Handle unexpected roles or undefined cases
            messages.error(request, 'Invalid role assigned to user.')
            return redirect('/')  # Or another fallback page (e.g., homepage)
            
@login_required
def leave_dashboard_employee(request):
    # Fetch the employee's leave data
     # Fetch all pending leave requests for the admin to approve or reject
    pending_leaves = Leave.objects.filter(status=Leave.Status.PENDING)

    # Fetch all leaves for the logged-in employee (employee-specific view)
    employee_leaves = Leave.objects.filter(employee=request.user)
    
    # Fetch the leave quotas for the logged-in user
    # Calculate leave type summary (total requests for each leave type)
    leave_type_counts = Counter(leave.get_leave_type_display() for leave in pending_leaves)

    # Convert the Counter object to a dictionary
    leave_type_summary = dict(leave_type_counts)

    # Fetch leave quotas for the logged-in admin (display quota for all employees, admin is authorized to view)
    leave_quotas = LeaveQuota.objects.filter(employee=request.user)

    # Initialize a dictionary to store remaining leave quotas for each leave type
    remaining_leave_quotas = {
        'Sick_Leave': 0,
        'Casual_Leave': 0,
        'Privilege_Leave': 0,
    }

    # Get the remaining leave quotas for the logged-in user (admin)
    for quota in leave_quotas:
        if quota.leave_type == LeaveQuota.LeaveType.SICK_LEAVE:
            remaining_leave_quotas['Sick_Leave'] = quota.remain_quota
        elif quota.leave_type == LeaveQuota.LeaveType.CASUAL_LEAVE:
            remaining_leave_quotas['Casual_Leave'] = quota.remain_quota
        elif quota.leave_type == LeaveQuota.LeaveType.PRIVILEGE_LEAVE:
            remaining_leave_quotas['Privilege_Leave'] = quota.remain_quota

    # Subtract the number of approved leaves from the remaining leave quotas
    for leave in employee_leaves:
        if leave.status == Leave.Status.APPROVED:
            if leave.leave_type == Leave.LeaveType.SICK_LEAVE:
                remaining_leave_quotas['Sick_Leave'] -= 1
            elif leave.leave_type == Leave.LeaveType.CASUAL_LEAVE:
                remaining_leave_quotas['Casual_Leave'] -= 1
            elif leave.leave_type == Leave.LeaveType.PRIVILEGE_LEAVE:
                remaining_leave_quotas['Privilege_Leave'] -= 1

    # Make sure the total leaves applied are in sync with the remaining quota
    # Ensure that any changes in the quota are reflected in the user's leave dashboard

    # Pass the leave data, leave type counts, and remaining leave quotas to the template
    return render(request, 'dashboard/leave_dashboard_employee.html', {
        'pending_leaves': pending_leaves,
        'employee_leaves': employee_leaves,
        'leave_type_summary': leave_type_summary,
        'remaining_leave_quotas': remaining_leave_quotas,
    })









@login_required
def leave_dashboard_admin(request):
    # Fetch all pending leave requests for the admin to approve or reject
    pending_leaves = Leave.objects.filter(status=Leave.Status.PENDING)

    # Fetch all leaves for the logged-in employee (employee-specific view)
    employee_leaves = Leave.objects.filter(employee=request.user)

    # Calculate leave type summary (total requests for each leave type)
    leave_type_counts = Counter(leave.get_leave_type_display() for leave in pending_leaves)

    # Convert the Counter object to a dictionary
    leave_type_summary = dict(leave_type_counts)

    # Fetch leave quotas for the logged-in admin (display quota for all employees, admin is authorized to view)
    leave_quotas = LeaveQuota.objects.filter(employee=request.user)

    # Initialize a dictionary to store remaining leave quotas for each leave type
    remaining_leave_quotas = {
        'Sick_Leave': 0,
        'Casual_Leave': 0,
        'Privilege_Leave': 0,
    }

    # Get the remaining leave quotas for the logged-in user (admin)
    for quota in leave_quotas:
        if quota.leave_type == LeaveQuota.LeaveType.SICK_LEAVE:
            remaining_leave_quotas['Sick_Leave'] = quota.remain_quota
        elif quota.leave_type == LeaveQuota.LeaveType.CASUAL_LEAVE:
            remaining_leave_quotas['Casual_Leave'] = quota.remain_quota
        elif quota.leave_type == LeaveQuota.LeaveType.PRIVILEGE_LEAVE:
            remaining_leave_quotas['Privilege_Leave'] = quota.remain_quota

    # Subtract the number of approved leaves from the remaining leave quotas
    for leave in employee_leaves:
        if leave.status == Leave.Status.APPROVED:
            if leave.leave_type == Leave.LeaveType.SICK_LEAVE:
                remaining_leave_quotas['Sick_Leave'] -= 1
            elif leave.leave_type == Leave.LeaveType.CASUAL_LEAVE:
                remaining_leave_quotas['Casual_Leave'] -= 1
            elif leave.leave_type == Leave.LeaveType.PRIVILEGE_LEAVE:
                remaining_leave_quotas['Privilege_Leave'] -= 1

    # Pass the pending leaves, employee leaves, leave type summary, and leave quotas to the template
    return render(request, 'dashboard/leave_dashboard_admin.html', {
        'pending_leaves': pending_leaves,
        'employee_leaves': employee_leaves,
        'leave_type_summary': leave_type_summary,
        'remaining_leave_quotas': remaining_leave_quotas,  # Pass remaining leave quotas for the logged-in admin
    })

    
    
@login_required
def apply_leave(request):
    # Fetch the leave quotas for the logged-in user
    leave_quotas = LeaveQuota.objects.filter(employee=request.user)

    # Initialize a list to hold available leave types based on remaining quotas
    available_leave_types = []
    
    remaining_leave_quotas = {
        'Sick_Leave': 0,
        'Casual_Leave': 0,
        'Privilege_Leave': 0,
    }

    # Get the remaining leave quotas for the current user
    for quota in leave_quotas:
        if quota.leave_type == LeaveQuota.LeaveType.SICK_LEAVE:
            remaining_leave_quotas['Sick_Leave'] = quota.remain_quota
        elif quota.leave_type == LeaveQuota.LeaveType.CASUAL_LEAVE:
            remaining_leave_quotas['Casual_Leave'] = quota.remain_quota
        elif quota.leave_type == LeaveQuota.LeaveType.PRIVILEGE_LEAVE:
            remaining_leave_quotas['Privilege_Leave'] = quota.remain_quota
            
    # Check available leave types based on the remaining quota
    for quota in leave_quotas:
        if quota.remain_quota > 0:  # Only add leave types with a remaining quota
            available_leave_types.append(quota.leave_type)

    if request.method == 'POST':
        leave_type = request.POST.get('leave_type')

        # Check if the selected leave type is available (i.e., has remaining quota)
        if leave_type not in available_leave_types:
            messages.error(request, 'Selected leave type is not available due to insufficient quota.')
            return redirect('apply_leave')  # Redirect back to the leave application form

        reason = request.POST.get('reason')
        start_date_str = request.POST.get('start_date')
        end_date_str = request.POST.get('end_date')

        # Convert the date strings to datetime objects
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

        # Calculate total days of leave
        total_days = (end_date - start_date).days + 1  # Total days of leave

        # Create a new leave request
        leave = Leave.objects.create(
            employee=request.user,
            leave_type=leave_type,
            reason=reason,
            start_date=start_date,
            end_date=end_date,
            total_days=total_days,
            status=Leave.Status.PENDING
        )

        # Redirect based on the user's role
        user_role = request.user.first_name
        if user_role == 'Admin':
            return redirect('leave_dashboard_admin')
        elif user_role == 'Employee':
            return redirect('leave_dashboard_employee')
        else:
            return redirect('/')  # In case the role is unknown

    return render(request, 'dashboard/apply_leave.html', {
        'available_leave_types': available_leave_types,'remaining_leave_quotas': remaining_leave_quotas,  # Pass available leave types
    })


@login_required
def edit_leave(request, leave_id):
    leave = get_object_or_404(Leave, leave_id=leave_id)

    if request.method == 'POST':
        leave_type = request.POST.get('leave_type')
        reason = request.POST.get('reason')
        start_date_str = request.POST.get('start_date')
        end_date_str = request.POST.get('end_date')

        # Convert the date strings to datetime objects
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

        # Calculate total days of leave
        total_days = (end_date - start_date).days + 1

        # Update the leave request with the new details
        leave.leave_type = leave_type
        leave.reason = reason
        leave.start_date = start_date
        leave.end_date = end_date
        leave.total_days = total_days
        leave.status = Leave.Status.PENDING  # Reset status to PENDING if edited
        leave.save()

        # Redirect to the employee dashboard after editing the leave
        return redirect('leave_dashboard_employee')

    return render(request, 'dashboard/edit_leave.html', {'leave': leave})

# Admin/Manager can approve or reject leave
@login_required
def approve_or_reject_leave(request, leave_id):
    leave = Leave.objects.get(leave_id=leave_id)

    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'approve':
            leave.status = Leave.Status.APPROVED
            leave.approved_by = request.user
            leave.save()
        elif action == 'reject':
            leave.status = Leave.Status.REJECTED
            leave.approved_by = request.user
            leave.save()

        # After approval or rejection, redirect to the admin dashboard
        return redirect('leave_dashboard_admin')

    return render(request, 'dashboard/approve_or_reject_leave.html', {'leave': leave})



def leave_quota_view(request):
    if request.method == "POST":
        employee_id = request.POST.get('employee')
        sl_quota = request.POST.get('sl_quota')
        pl_quota = request.POST.get('pl_quota')
        cl_quota = request.POST.get('cl_quota')

        quotas = [
            {'leave_type': 'SL', 'total_quota': int(sl_quota)},
            {'leave_type': 'PL', 'total_quota': int(pl_quota)},
            {'leave_type': 'CL', 'total_quota': int(cl_quota)}
        ]

        employee = get_object_or_404(Employee, employee_id=employee_id)

        for quota in quotas:
            LeaveQuota.objects.update_or_create(
                employee=employee,
                leave_type=quota['leave_type'],
                defaults={
                    'total_quota': quota['total_quota'],
                    'used_quota': 0  # Reset used quota for simplicity
                }
            )

        return redirect("leave_quota_view")
    # Fetch all employees and their respective leave quotas
    employees = Employee.objects.all()
    leave_quotas = LeaveQuota.objects.select_related('employee')

    # Group leave quotas by employee
    employee_data = {}
    for quota in leave_quotas:
        if quota.employee.employee_id not in employee_data:
            employee_data[quota.employee.employee_id] = {
                'employee_name': quota.employee.username,
                'SL': 0,  # Default values
                'PL': 0,
                'CL': 0
            }
        employee_data[quota.employee.employee_id][quota.leave_type] = quota.remain_quota

    return render(request, 'dashboard/leave_quota.html', {
        'employees': employees,
        'employee_data': employee_data
    })

def edit_leave_quota_view(request, employee_id):
    # Fetch the employee and their leave quotas
    employee = get_object_or_404(Employee, employee_id=employee_id)
    leave_quotas = LeaveQuota.objects.filter(employee=employee)

    # Initialize quotas
    sl_quota = leave_quotas.filter(leave_type='SL').first()
    pl_quota = leave_quotas.filter(leave_type='PL').first()
    cl_quota = leave_quotas.filter(leave_type='CL').first()

    # Handle form submission
    if request.method == 'POST':
        # Convert form data to integers
        sl_quota_value = int(request.POST.get('sl_quota', 0))
        pl_quota_value = int(request.POST.get('pl_quota', 0))
        cl_quota_value = int(request.POST.get('cl_quota', 0))

        # Update leave quotas
        if sl_quota:
            sl_quota.total_quota = sl_quota_value
            sl_quota.save()
        if pl_quota:
            pl_quota.total_quota = pl_quota_value
            pl_quota.save()
        if cl_quota:
            cl_quota.total_quota = cl_quota_value
            cl_quota.save()

        return redirect('leave_quota_view')  # Replace 'leave_quota' with the correct URL name for your main quota page

    context = {
        'employee': employee,
        'sl_quota': sl_quota.total_quota if sl_quota else 0,
        'pl_quota': pl_quota.total_quota if pl_quota else 0,
        'cl_quota': cl_quota.total_quota if cl_quota else 0,
    }
    return render(request, 'dashboard/edit_leave_quota.html', context)