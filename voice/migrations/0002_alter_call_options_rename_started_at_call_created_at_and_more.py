# Generated by Django 5.2.4 on 2025-07-24 09:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('voice', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='call',
            options={'ordering': ['-created_at']},
        ),
        migrations.RenameField(
            model_name='call',
            old_name='started_at',
            new_name='created_at',
        ),
        migrations.RemoveField(
            model_name='call',
            name='contact',
        ),
        migrations.RemoveField(
            model_name='call',
            name='ended_at',
        ),
        migrations.AddField(
            model_name='call',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AlterField(
            model_name='call',
            name='call_sid',
            field=models.CharField(default=2, max_length=100, unique=True),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='call',
            name='direction',
            field=models.CharField(choices=[('incoming', 'Incoming'), ('outgoing', 'Outgoing')], max_length=10),
        ),
        migrations.AlterField(
            model_name='call',
            name='duration',
            field=models.IntegerField(blank=True, help_text='Duration in seconds', null=True),
        ),
        migrations.AlterField(
            model_name='call',
            name='status',
            field=models.CharField(choices=[('queued', 'Queued'), ('ringing', 'Ringing'), ('in-progress', 'In Progress'), ('completed', 'Completed'), ('failed', 'Failed'), ('busy', 'Busy'), ('no-answer', 'No Answer'), ('canceled', 'Canceled')], default='queued', max_length=20),
        ),
    ]
