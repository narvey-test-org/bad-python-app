import os

UPLOAD_DIR = "/var/uploads"
SAFE_DIR = "/var/safe"

# ruleid: path-traversal-open-os-path-join
# SHOULD MATCH — user_filename flows directly into os.path.join then open()
def bad_file_read(user_filename):
    path = os.path.join(UPLOAD_DIR, user_filename)
    with open(path, 'r') as f:
        return f.read()

# ruleid: path-traversal-open-os-path-join
# SHOULD MATCH — inline: os.path.join passed directly into open() in one expression
def bad_inline(user_filename):
    with open(os.path.join(UPLOAD_DIR, user_filename), 'rb') as f:
        return f.read()

# ok: path-traversal-open-os-path-join
# SHOULD NOT MATCH — hardcoded filename, no user input
def safe_hardcoded():
    path = os.path.join(UPLOAD_DIR, "config.json")
    with open(path, 'r') as f:
        return f.read()

# ok: path-traversal-open-os-path-join
# SHOULD NOT MATCH — path is validated before open()
def safe_validated(user_filename):
    joined = os.path.join(UPLOAD_DIR, user_filename)
    safe = os.path.abspath(joined)
    if not safe.startswith(os.path.abspath(UPLOAD_DIR)):
        raise ValueError("Path traversal detected")
    with open(safe, 'r') as f:
        return f.read()
