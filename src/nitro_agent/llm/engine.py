"""
LLM engine factory for Nitro-Agent.

Provider constructors and parameters follow the official LangChain integration docs:
- OpenAI:   https://python.langchain.com/docs/integrations/chat/openai
- Anthropic: https://python.langchain.com/docs/integrations/chat/anthropic
- Gemini:   https://python.langchain.com/docs/integrations/chat/google_generative_ai

Env vars: OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY.
"""
import os
from langchain_core.language_models.chat_models import BaseChatModel

SUPPORTED_PROVIDERS = ("local", "openai", "anthropic", "gemini")

_ENV_KEY_MAP = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
}

_PROVIDER_DISPLAY = {
    "local": "Local llama-server",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "gemini": "Google Gemini",
}


def _validate_api_key(provider: str) -> str:
    env_var = _ENV_KEY_MAP[provider]
    key = os.environ.get(env_var, "").strip()
    if not key:
        raise ValueError(
            f"LLM provider '{provider}' requires the {env_var} environment variable. "
            f"Set it in your .env file or export it before running nitro-agent."
        )
    return key


def _build_local_engine() -> BaseChatModel:
    from langchain_openai import ChatOpenAI

    base_url = os.environ.get("LLAMA_SERVER_BASE_URL", "http://127.0.0.1:8080/v1")
    return ChatOpenAI(
        base_url=base_url,
        api_key="not-needed",
        model="local-model",
        temperature=0.0,
        max_tokens=4096,
        max_retries=3,
        timeout=300.0,
    )


def _build_openai_engine() -> BaseChatModel:
    from langchain_openai import ChatOpenAI

    api_key = _validate_api_key("openai")
    model = os.environ.get("OPENAI_MODEL", "gpt-4o")
    return ChatOpenAI(
        api_key=api_key,
        model=model,
        temperature=0.0,
        max_tokens=4096,
        max_retries=3,
        timeout=120.0,
    )


def _build_anthropic_engine() -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic

    api_key = _validate_api_key("anthropic")
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    return ChatAnthropic(
        api_key=api_key,
        model=model,
        temperature=0.0,
        max_tokens=4096,
        max_retries=3,
        timeout=120.0,
    )


def _build_gemini_engine() -> BaseChatModel:
    from langchain_google_genai import ChatGoogleGenerativeAI

    api_key = _validate_api_key("gemini")
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    return ChatGoogleGenerativeAI(
        google_api_key=api_key,
        model=model,
        temperature=0.0,
        max_output_tokens=4096,
        max_retries=3,
        timeout=120.0,
    )


_BUILDERS = {
    "local": _build_local_engine,
    "openai": _build_openai_engine,
    "anthropic": _build_anthropic_engine,
    "gemini": _build_gemini_engine,
}

# Module-level state so the provider can be set once from the CLI
_active_provider: str = "local"


def set_provider(provider: str) -> None:
    global _active_provider
    provider = provider.lower().strip()
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unsupported LLM provider '{provider}'. "
            f"Choose from: {', '.join(SUPPORTED_PROVIDERS)}"
        )
    _active_provider = provider


def get_provider() -> str:
    return _active_provider


def get_llm_engine() -> BaseChatModel:
    provider = _active_provider
    try:
        engine = _BUILDERS[provider]()
    except ImportError as e:
        pkg = {
            "anthropic": "langchain-anthropic",
            "gemini": "langchain-google-genai",
        }.get(provider, "")
        if pkg:
            raise ImportError(
                f"Provider '{provider}' requires the '{pkg}' package. "
                f"Install it with: pip install {pkg}"
            ) from e
        raise
    return engine
