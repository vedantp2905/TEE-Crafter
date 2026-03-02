from langchain_openai import ChatOpenAI
import os

def get_llm_engine() -> ChatOpenAI:
    """
    Initializes and returns the LangChain ChatOpenAI engine configured 
    to connect to a local llama-server instance.
    """
    # Use environment variable if set, otherwise default to local llama-server
    base_url = os.environ.get("LLAMA_SERVER_BASE_URL", "http://127.0.0.1:8080/v1")
    
    # We use ChatOpenAI because llama-server exposes an OpenAI-compatible API
    llm = ChatOpenAI(
        base_url=base_url,
        api_key="not-needed", # Local server doesn't require an actual key
        model="local-model", # The model name is ignored by llama-server usually
        temperature=0.0, # We want deterministic, code-generating output
        max_tokens=4096,
        max_retries=3, # Help recover if the server throws an intermittent error
        timeout=300.0, # 5 minutes timeout (local LLMs can be slow to generate on CPU/low VRAM)
    )
    return llm
