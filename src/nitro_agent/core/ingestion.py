import os
import glob
from typing import Optional, Dict

def ingest_directory(source_path: str) -> Optional[Dict[str, str]]:
    """
    Reads Python files and dependency manifests in the given directory.
    
    Returns a dictionary containing:
      - 'python_code': Concatenated source code
      - 'dependencies': Contents of requirements.txt or pyproject.toml
    Returns None if no Python files are found.
    """
    if not os.path.isdir(source_path):
        raise ValueError(f"Source path is not a valid directory: {source_path}")

    python_files = glob.glob(os.path.join(source_path, "**/*.py"), recursive=True)
    
    if not python_files:
        return None

    combined_code = []
    
    for py_file in python_files:
        # Avoid ingesting virtual environments or hidden directories
        # os.sep is important here to avoid matching substrings like `myvenv.py`
        parts = py_file.split(os.sep)
        if any(ignored in parts for ignored in ['venv', '.venv', '.git', '__pycache__', '.cursor', 'node_modules']):
            continue
            
        with open(py_file, 'r', encoding='utf-8') as f:
            file_content = f.read()
            # Add a clear separator indicating the file name for the LLM
            header = f"\n\n# --- File: {os.path.relpath(py_file, source_path)} ---\n\n"
            combined_code.append(header + file_content)

    # Ingest dependencies if they exist to pass to the Dockerfile agent
    dependencies_content = "No dependency files (requirements.txt/pyproject.toml) found."
    for dep_file in ["requirements.txt", "pyproject.toml", "Pipfile"]:
        dep_path = os.path.join(source_path, dep_file)
        if os.path.exists(dep_path):
            with open(dep_path, 'r', encoding='utf-8') as f:
                dependencies_content = f"\n\n# --- File: {dep_file} ---\n\n" + f.read()
            break  # Just grab the first primary one we find

    return {
        "python_code": "".join(combined_code),
        "dependencies": dependencies_content
    }
