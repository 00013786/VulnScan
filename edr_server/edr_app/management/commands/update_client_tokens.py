from django.core.management.base import BaseCommand
import uuid
from edr_app.models import Client

class Command(BaseCommand):
    help = 'Updates all clients with unique auth tokens'

    def handle(self, *args, **options):
        clients = Client.objects.all()
        for client in clients:
            client.auth_token = str(uuid.uuid4())
            client.save()
            self.stdout.write(self.style.SUCCESS(f'Successfully updated token for client {client.hostname}'))
