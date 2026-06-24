# Widen CapAuthKeyRegistry fingerprint columns from 40 to 64 hex chars so
# post-quantum / OpenPGP v6 (RFC 9580) fingerprints (64 hex) are accepted
# alongside classical v4 fingerprints (40 hex).
#
# NOTE FOR CHEF: This migration MUST be applied by hand on the live authentik
# DB (`python manage.py migrate capauth` inside the authentik environment).
# Widening a CharField/VARCHAR column is a non-destructive operation (no data
# loss, existing 40-hex rows are untouched). It is NOT auto-applied here.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("capauth", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="capauthkeyregistry",
            name="fingerprint",
            field=models.CharField(
                help_text="Full uppercase PGP fingerprint: 40 (v4) or 64 (v6) hex.",
                max_length=64,
                primary_key=True,
                serialize=False,
            ),
        ),
        migrations.AlterField(
            model_name="capauthkeyregistry",
            name="linked_to",
            field=models.CharField(
                blank=True,
                help_text="Primary fingerprint for multi-device identities: 40 (v4) or 64 (v6) hex.",
                max_length=64,
                null=True,
            ),
        ),
    ]
