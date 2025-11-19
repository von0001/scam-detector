# backend/ai/groq_client.py

from groq import Groq
import os

# Read key from env
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

client = Groq(api_key=GROQ_API_KEY)


def groq_chat(messages, model="llama-3.1-70b-versatile"):
    """
    Lightweight helper to call Groq chat completions.
    Returns the text output only.
    """
    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.2,
    )
    return resp.choices[0].message.content.strip()