from django.conf import settings
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0005_workspacemembership_is_archived_archived_at"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="workspace",
            name="owner",
        ),
    ]
