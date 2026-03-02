import os
import shutil
import datetime
import json

def _load_template(filename: str) -> str:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, "..", "templates", filename)
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def render_dockerfile_template() -> str:
    """Returns the static Dockerfile template."""
    return _load_template("Dockerfile.template")

def render_client_template(pcr_hashes: dict = None, root_ca: str = "") -> str:
    """
    Renders the static Python client script template, injecting the 
    root CA and expected PCR hashes.
    """
    template_str = _load_template("client.template.py")
    
    # Format the PCR bindings into a clean Python dictionary string
    pcr_bindings_str = "{}"
    if pcr_hashes:
        pcr_bindings_str = json.dumps(pcr_hashes, indent=4)
        
    # Use replace() instead of format() to avoid conflicts with Python's {} syntax in the template
    client_code = template_str.replace("{root_ca}", root_ca.strip())
    client_code = client_code.replace("{pcr_bindings}", pcr_bindings_str)
    
    return client_code

def render_host_proxy_template() -> str:
    """Returns the static Host API Proxy script."""
    return _load_template("host_proxy.template.py")

def stage_artifacts(source_dir: str, vsock_code: str, dockerfile_content: str, base_build_dir: str = "build") -> str:
    """
    Saves the generated vsock wrapper and Dockerfile into a dedicated 
    timestamped build staging directory. Copies the user's original source code there as well.
    
    Returns the absolute path to the build directory.
    """
    # 1. Create a timestamped build directory under builds/
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    source_name = os.path.basename(os.path.abspath(source_dir)) or "app"
    build_dir_name = f"{source_name}_{base_build_dir}_{timestamp}"
    build_path = os.path.abspath(os.path.join("builds", build_dir_name))
    os.makedirs(build_path, exist_ok=True)
    
    # 2. Copy user's original source files (dependencies might be needed)
    # Use ignore_patterns to safely avoid copying virtual envs or huge build artifacts
    ignore_func = shutil.ignore_patterns('venv', '.git', '__pycache__', '.env', '*.pyc', '.cursor', 'node_modules', 'build_*')
    
    for item in os.listdir(source_dir):
        s = os.path.join(source_dir, item)
        d = os.path.join(build_path, item)
        if os.path.isdir(s):
            if item not in ["venv", ".git", "__pycache__", ".cursor", "node_modules"]:
                shutil.copytree(s, d, ignore=ignore_func)
        else:
            shutil.copy2(s, d)

    # 3. Write the generated vsock script
    vsock_path = os.path.join(build_path, "app_vsock.py")
    with open(vsock_path, "w", encoding="utf-8") as f:
        f.write(vsock_code)
        
    # 4. Write the Dockerfile
    dockerfile_path = os.path.join(build_path, "Dockerfile")
    with open(dockerfile_path, "w", encoding="utf-8") as f:
        f.write(dockerfile_content)

    # 5. Write the Host Proxy
    host_proxy_path = os.path.join(build_path, "host_proxy.py")
    with open(host_proxy_path, "w", encoding="utf-8") as f:
        f.write(render_host_proxy_template())

    return build_path
