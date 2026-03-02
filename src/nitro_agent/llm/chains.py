import json
import os
from typing import Tuple
from .engine import get_llm_engine
from .prompts.templates import get_vsock_prompt
from nitro_agent.core.verification import verify_python_compile

def _load_template(filename: str) -> str:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, "..", "templates", filename)
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def _clean_markdown_code_blocks(text: str) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    cleaned = []
    in_block = False
    has_code_blocks = any(line.strip().startswith("```") for line in lines)
    if not has_code_blocks:
        return text.strip()
    for line in lines:
        if line.strip().startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            cleaned.append(line)
    if not cleaned:
        return text.strip()
    return "\n".join(cleaned).strip()

def generate_vsock_wrapper(app_description: str, source_code: str, data_content: str = "", max_retries: int = 3) -> str:
    """
    Executes the LangChain process to generate a vsock Python wrapper.
    Now uses a static template for networking/attestation, and the LLM
    only fills in the `user_imports` and `user_logic`.
    """
    llm = get_llm_engine()
    last_error = ""
    vsock_template = _load_template("app_vsock.template.py")
    
    for attempt in range(max_retries + 1):
        prompt = get_vsock_prompt(error_feedback=last_error)
        chain = prompt | llm

        inputs = {
            "app_description": app_description,
            "source_code": source_code,
            "data_content": data_content,
            "error_feedback": last_error  # Always provide it, even if empty
        }
            
        result = chain.invoke(inputs)
        raw_content = getattr(result, "content", None) or str(result) or ""
        cleaned_json_str = _clean_markdown_code_blocks(raw_content)

        try:
            text = raw_content.strip()
            if text.startswith("```json"): text = text[7:]
            if text.startswith("```"): text = text[3:]
            if text.endswith("```"): text = text[:-3]
            text = text.strip()
            
            import json
            parsed = json.loads(text)
            
            # The prompt instructs the model to return arrays of strings
            imports_list = parsed.get("user_imports", [])
            logic_list = parsed.get("user_logic", ["    return data"])
            
            if isinstance(imports_list, str):
                user_imports = imports_list
            else:
                user_imports = "\n".join(imports_list)
                
            if isinstance(logic_list, str):
                user_logic = logic_list
            else:
                user_logic = "\n".join(logic_list)

            candidate_code = vsock_template.replace("{user_imports}", user_imports).replace("{user_logic}", user_logic)
        except Exception as e:
            last_error = f"Failed to parse model response: {e}. Output was:\n{raw_content}"
            if attempt < max_retries:
                print(f"  [Attempt {attempt+1}] Parse failed. Retrying...")
                continue
            raise ValueError(f"Model failed to output parseable logic: {e}\nRaw output was:\n{raw_content}")

        # Validate with pyflakes
        valid, error_msg = verify_python_compile(candidate_code)
        if valid:
            return candidate_code

        last_error = (
            f"Python validation failed for the injected code:\n{error_msg}\n\n"
            "This was the full generated file that failed:\n---\n"
            f"{candidate_code}\n---\n"
            "Fix your 'user_imports' and 'user_logic' to resolve this."
        )
        print(f"  [Vsock attempt {attempt+1}/{max_retries + 1}] Validation failed. Retrying with feedback...")

    raise ValueError(f"Failed to generate valid Python code after {max_retries} attempts. Last error: {last_error}")