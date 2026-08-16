import os
from azure.storage.blob import BlobServiceClient


class BlobStore:
    def __init__(self, client):
        self.client = client

    def put(self, files):
        container = self.client.get_container_client("chat-uploads")
        return files


def create_blob_store():
    client = BlobServiceClient.from_connection_string(
        os.environ["AZURE_STORAGE_CONNECTION_STRING"]
    )
    return BlobStore(client)
