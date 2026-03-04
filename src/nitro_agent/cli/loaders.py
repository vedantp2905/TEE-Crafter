"""Load template and resource files from the package."""

import os


def load_remote_setup_template() -> str:
    """Load the remote host setup script template from templates dir."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, "..", "templates", "remote_setup_script.sh")
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()


def load_root_ca() -> str:
    """Load the AWS Nitro Root CA PEM from the package."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    root_path = os.path.join(current_dir, "..", "resources", "root.pem")
    if os.path.exists(root_path):
        with open(root_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""
