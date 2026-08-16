import os
from fastapi import FastAPI
from azure.identity import DefaultAzureCredential
from .blob import create_blob_store
from .cosmos import create_cosmos_store
from .graph import create_graph_index
from .secrets import create_secret_reader
from .telemetry import create_telemetry
from .foundry import create_foundry_agent


def create_app():
    credential = DefaultAzureCredential()
    blobs = create_blob_store()
    cosmos = create_cosmos_store()
    graph = create_graph_index()
    secrets = create_secret_reader(credential)
    telemetry = create_telemetry()
    foundry = create_foundry_agent()
    app = FastAPI()

    @app.post("/chat")
    async def chat(body: dict):
        telemetry.track("chat.start")
        secrets.get_secret("foundry-endpoint")
        attachments = blobs.put(body.get("attachments") or [])
        neighbors = graph.retrieve(body["text"])
        answer = foundry.run(body["text"], neighbors)
        cosmos.upsert({
            "text": body["text"],
            "sessionId": body.get("sessionId"),
            "answer": answer,
            "attachments": attachments,
        })
        telemetry.track("chat.complete")
        return {"ok": True, "answer": answer}

    @app.get("/health")
    async def health():
        return {"ok": True}

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
