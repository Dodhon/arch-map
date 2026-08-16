import os
from azure.cosmos import CosmosClient


class CosmosStore:
    def __init__(self, container):
        self.container = container

    def upsert(self, doc):
        return self.container.items.upsert(doc)


def create_cosmos_store():
    client = CosmosClient(
        os.environ["AZURE_COSMOS_ENDPOINT"],
        credential=os.environ["AZURE_COSMOS_KEY"],
    )
    container = client.get_database_client("chat").get_container_client("turns")
    return CosmosStore(container)
