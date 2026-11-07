import subprocess
from pathlib import Path

repo_url = "https://github.com/Deep-Jiwan/vul-python-app"
script_dir = Path(__file__).parent
clone_path = script_dir / "repo"

# Remove existing repo if it exists
if clone_path.exists():
    import shutil
    shutil.rmtree(clone_path)
    print(f"✓ Removed existing repo")

subprocess.run(["git", "clone", repo_url, str(clone_path)], check=True)
print(f"✓ Cloned to {clone_path}")