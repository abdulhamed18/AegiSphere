from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_workspace_rbac"),
    ]

    operations = [
        migrations.AddField(
            model_name="workspacemembership",
            name="deactivated_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
