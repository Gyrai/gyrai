"""A fake OpenAI-compatible model server for tests and demos. It echoes the last
user message back (so masking/unmasking is observable) and supports streaming.

  uvicorn mock_upstream:app --port 9999
"""
import json
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="Mock OpenAI")


def _last_user_text(messages):
    """Return the text of the most recent user message, handling plain and multi-part content."""
    for m in reversed(messages or []):
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, str):
                return c
            if isinstance(c, list):
                return " ".join(p.get("text", "") for p in c if isinstance(p, dict) and p.get("type") == "text")
    return ""


@app.get("/v1/models")
def models():
    return {"object": "list", "data": [{"id": "mock-1", "object": "model"}]}


@app.post("/v1/embeddings")
async def embeddings(request: Request):
    """Return a fixed three-number vector per input; real vectors are not needed for tests."""
    body = await request.json()
    inputs = body["input"] if isinstance(body["input"], list) else [body["input"]]
    return {"object": "list", "model": body.get("model", "mock-embed"),
            "data": [{"object": "embedding", "index": i, "embedding": [0.1, 0.2, 0.3]} for i, _ in enumerate(inputs)],
            "usage": {"prompt_tokens": 3, "total_tokens": 3}}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    """Echo the last user message, streamed word by word when `stream` is true."""
    body = await request.json()
    echo = "You said: " + _last_user_text(body.get("messages"))
    rid = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    if body.get("stream"):
        async def gen():
            words = echo.split(" ")
            for i, w in enumerate(words):
                chunk = {"id": rid, "object": "chat.completion.chunk", "created": int(time.time()), "model": body.get("model"),
                         "choices": [{"index": 0, "delta": {"content": (w if i == 0 else " " + w)}, "finish_reason": None}]}
                yield f"data: {json.dumps(chunk)}\n\n"
            yield f"data: {json.dumps({'id': rid, 'object': 'chat.completion.chunk', 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")
    return JSONResponse({
        "id": rid, "object": "chat.completion", "created": int(time.time()), "model": body.get("model"),
        "choices": [{"index": 0, "message": {"role": "assistant", "content": echo}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": len(echo.split()), "total_tokens": 10 + len(echo.split())},
    })
