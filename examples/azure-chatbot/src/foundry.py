import os
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential


class FoundryAgent:
    def __init__(self, client, agent):
        self.client = client
        self.agent = agent

    def run(self, text, neighbors):
        thread = self.client.agents.create_thread()
        self.client.agents.create_message(
            thread_id=thread.id,
            role="user",
            content=f"{text}\n\ncontext={neighbors}",
        )
        return self.client.agents.create_and_process_run(
            thread_id=thread.id,
            agent_id=self.agent.id,
        )


def create_foundry_agent():
    client = AIProjectClient(
        endpoint=os.environ["AZURE_AI_PROJECT_ENDPOINT"],
        credential=DefaultAzureCredential(),
    )
    agent = client.agents.create_agent(
        model=os.environ["AZURE_AI_MODEL_DEPLOYMENT_NAME"],
        name="chat-agent",
        instructions="Answer using retrieved graph neighbors when present.",
    )
    return FoundryAgent(client, agent)
