# Generated by Django 4.2.7 on 2024-12-21 16:12

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('edr_app', '0005_client_auth_token_client_is_active'),
    ]

    operations = [
        migrations.CreateModel(
            name='Command',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('command', models.CharField(max_length=255)),
                ('args', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('executed', models.BooleanField(default=False)),
                ('executed_at', models.DateTimeField(blank=True, null=True)),
                ('response', models.TextField(blank=True)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='commands', to='edr_app.client')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
