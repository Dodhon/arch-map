import os
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection


class GraphIndex:
    def __init__(self, client):
        self.client = client

    def retrieve(self, text):
        return self.client.submit(
            "g.V().has('chunk', 'text', text).out('near').limit(8)",
            {"text": text},
        )


def create_graph_index():
    client = DriverRemoteConnection(os.environ["COSMOS_GREMLIN_ENDPOINT"], "g")
    return GraphIndex(client)
