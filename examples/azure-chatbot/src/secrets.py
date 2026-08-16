import os
from azure.keyvault.secrets import SecretClient


class SecretReader:
    def __init__(self, client):
        self.client = client

    def get_secret(self, name):
        secret = self.client.get_secret(name)
        return secret.value


def create_secret_reader(credential):
    client = SecretClient(os.environ["AZURE_KEY_VAULT_URL"], credential)
    return SecretReader(client)
