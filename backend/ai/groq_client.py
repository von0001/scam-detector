# backend/ai/groq_client.py

from groq import Groq
import os

_client = None

def get_client():
    global _client
    if _client is None:
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set.")
        _client = Groq(api_key=key)
    return _client


def groq_chat(messages, model="llama-3.1-70b-versatile"):
    """
    Safe Groq chat helper with lazy init.
    """
    client = get_client()
    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.2,
    )
    return resp.choices[0].message.content.strip()