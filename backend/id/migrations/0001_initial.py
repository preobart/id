# Generated manually
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('waffle', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='FlagCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target', models.CharField(choices=[('frontend', 'Frontend'), ('backend', 'Backend'), ('both', 'Both')], default='both', help_text='Target audience for this flag (frontend, backend, or both)', max_length=10)),
                ('description', models.TextField(blank=True, help_text='Description of what this flag controls')),
                ('flag', models.OneToOneField(help_text='The flag this category belongs to', on_delete=django.db.models.deletion.CASCADE, related_name='category', to='waffle.flag')),
            ],
            options={
                'verbose_name': 'Flag Category',
                'verbose_name_plural': 'Flag Categories',
            },
        ),
    ]

