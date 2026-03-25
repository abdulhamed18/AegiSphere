# Phase 3 – Final completion: explicit leave tracking (left_at).
# Backward compatible: deactivated_at retained.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0009_alter_customuser_managers'),
    ]

    operations = [
        migrations.AddField(
            model_name='workspacemembership',
            name='left_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
