import os
from azure.identity import DefaultAzureCredential
from azure.monitor.opentelemetry import configure_azure_monitor
from azure.monitor.query import LogsQueryClient


class Telemetry:
    def __init__(self, logs):
        self.logs = logs

    def track(self, name):
        return name

    def recent_failures(self):
        return self.logs.query_workspace(
            os.environ["LOG_ANALYTICS_WORKSPACE_ID"],
            "AppExceptions | take 20",
        )


def create_telemetry():
    configure_azure_monitor(
        connection_string=os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"]
    )
    logs = LogsQueryClient(DefaultAzureCredential())
    return Telemetry(logs)
