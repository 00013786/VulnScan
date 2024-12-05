# Generated by Django 4.2.7 on 2024-12-05 00:28

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('edr_app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='port',
            name='service_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='port',
            name='service_version',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='process',
            name='version',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='affected_software',
            field=models.CharField(default='Unknown', max_length=255),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='affected_versions',
            field=models.CharField(default='*', max_length=255),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='related_ports',
            field=models.ManyToManyField(blank=True, related_name='vulnerabilities', to='edr_app.port'),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='related_processes',
            field=models.ManyToManyField(blank=True, related_name='vulnerabilities', to='edr_app.process'),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='severity',
            field=models.CharField(choices=[('CRITICAL', 'Critical'), ('HIGH', 'High'), ('MEDIUM', 'Medium'), ('LOW', 'Low')], default='MEDIUM', max_length=20),
        ),
        migrations.CreateModel(
            name='VulnerabilityMatch',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('match_type', models.CharField(choices=[('PROCESS', 'Process Match'), ('PORT', 'Port Match'), ('SERVICE', 'Service Match')], max_length=20)),
                ('confidence_score', models.FloatField(default=0.0)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='edr_app.client')),
                ('port', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='edr_app.port')),
                ('process', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='edr_app.process')),
                ('vulnerability', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='edr_app.vulnerability')),
            ],
            options={
                'unique_together': {('vulnerability', 'client', 'port'), ('vulnerability', 'client', 'process')},
            },
        ),
    ]