import os
from langchain_core.prompts import PromptTemplate

# Determine the absolute path to this directory
PROMPTS_DIR = os.path.dirname(os.path.abspath(__file__))

def _load_template(filename: str) -> str:
    """Helper to load a raw text template from disk."""
    path = os.path.join(PROMPTS_DIR, filename)
    with open(path, "r") as f:
        return f.read()

def get_vsock_prompt(error_feedback: str = "") -> PromptTemplate:
    """Returns the PromptTemplate for the vsock translation task."""
    template_str = _load_template("vsock_system_prompt.txt")
    if not error_feedback:
        template_str = template_str.replace("Previous Attempt Failed with Error:\n{error_feedback}\n\nYour task is to FIX the code based on the error above. Do not repeat the same mistake. Return ONLY the corrected Python code.", "")
    
    return PromptTemplate(
        template=template_str,
        input_variables=["app_description", "source_code", "data_content"] + (["error_feedback"] if error_feedback else [])
    )
