
from django.urls import path
from dashboard import views



urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('dashboard/create_department/', views.create_department, name='create_department'),
    path('dashboard/department/', views.viewDepartment, name='department'),
    path('delete/<int:deptid>/', views.delete_department, name='delete_department'),
    path('dashboard/update/<int:deptid>/', views.update_department, name='update'),
    path('dashboard/', views.role_dashboard, name='view_role'),
    path('dashboard/create_role/', views.create_role, name='create_role'),
    path('dashboard/update_role/<int:role_id>/', views.update_role, name='update_role'),
    path('dashboard/confirm_delete/<int:role_id>/', views.confirm_delete, name='confirm_delete'),

    path('dashboard/view_employee/', views.employee_dashboard, name='view_employee'),
    path('dashboard/create_employee/', views.create_employee, name='create_employee'),
    path('dashboard/update_employee/<int:employee_id>/', views.update_employee, name='update_employee'),
    path('dashboard/employee_delete/<int:employee_id>/', views.confirm_delete, name='employee_delete'),


    
    path('dashboard/login', views.userLogin, name='login'),
    path("logout/", views.userLogout, name="logout"),
    path('dashboard/forgot-password/', views.forgot_password, name='forgot_password'),
    path('dashboard/enter_otp/', views.enter_otp, name='enter_otp'),
    path('dashboard/reset-password/', views.reset_password, name='reset_password'),


    path('dashboard/view_tasks/', views.view_tasks, name='view_task'),
    path('dashboard/create_task/', views.add_task, name='create_task'),
    path('dashboard/update_task/<int:task_id>/', views.edit_task, name='update_task'),
    path('delete_task/<int:task_id>/', views.delete_task, name='delete_task'),
    path('mark_completed/<int:task_id>/', views.mark_completed, name='mark_completed'),
    path('task-details/<int:task_id>/', views.task_details, name='task_details'),


    #Review Employee:
    path('dashboard/reviews/', views.view_reviews, name='view_reviews'),
    path('dashboard/addreview/', views.add_review, name='add_review'),
    path('dashboard/see-comments/<int:review_id>/', views.see_comments, name='see_comments'),
    path('dashboard/edit-review/<int:review_id>/', views.edit_review, name='edit_review'),
    path('dashboard/delete-review/<int:review_id>/', views.delete_review, name='delete_review'),

     # Leave Management:
    path('dashboard/leave_dashboard/', views.leave_dashboard, name='leave_dashboard'),
    path('dashboard/leave_dashboard_employee/', views.leave_dashboard_employee, name='leave_dashboard_employee'),
    path('dashboard/leave_dashboard_admin/', views.leave_dashboard_admin, name='leave_dashboard_admin'),
    path('dashboard/apply_leave/', views.apply_leave, name='apply_leave'),
    path('dashboard/approve_or_reject_leave/<int:leave_id>/', views.approve_or_reject_leave, name='approve_or_reject_leave'),
    path('dashboard/edit_leave/<int:leave_id>/', views.edit_leave, name='edit_leave'),
    path('dashboard/leave-quota/', views.leave_quota_view, name='leave_quota_view'),
    path('dashboard/leave-quota/edit/<int:employee_id>/', views.edit_leave_quota_view, name='edit_leave_quota'),
    
]

