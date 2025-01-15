# Generated by Django 5.1.4 on 2025-01-13 15:38

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0004_review'),
    ]

    operations = [
        migrations.CreateModel(
            name='Leave',
            fields=[
                ('leave_id', models.AutoField(primary_key=True, serialize=False)),
                ('leave_type', models.CharField(choices=[('SL', 'Sick Leave'), ('CL', 'Casual Leave'), ('PL', 'Privilege Leave'), ('LWP', 'Leave Without Pay')], max_length=3)),
                ('reason', models.CharField(max_length=200)),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('total_days', models.PositiveIntegerField()),
                ('status', models.CharField(choices=[('approved', 'Approved'), ('rejected', 'Rejected'), ('pending', 'Pending')], default='pending', max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('approved_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='approved_leaves', to=settings.AUTH_USER_MODEL)),
                ('employee', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='leaves', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='LeaveQuota',
            fields=[
                ('quota_id', models.AutoField(primary_key=True, serialize=False)),
                ('leave_type', models.CharField(choices=[('SL', 'Sick Leave'), ('CL', 'Casual Leave'), ('PL', 'Privilege Leave'), ('LWP', 'Leave Without Pay')], max_length=3)),
                ('total_quota', models.PositiveIntegerField()),
                ('used_quota', models.PositiveIntegerField(default=0)),
                ('remain_quota', models.PositiveIntegerField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('employee', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='leave_quotas', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]