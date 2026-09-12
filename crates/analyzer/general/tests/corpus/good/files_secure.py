"""Correct file handling: open-and-handle, mkstemp, 0600, defused XML."""
import os
import tempfile
import defusedxml.ElementTree as ET
from flask import request
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"pdf", "png"}


def read_if_present(path):
    try:
        with open(path) as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def scratch():
    fd, name = tempfile.mkstemp()
    os.chmod(name, 0o600)
    return fd, name


def parse_xml():
    return ET.fromstring(request.data)


def upload():
    f = request.files["doc"]
    name = secure_filename(f.filename)
    if name.rsplit(".", 1)[-1].lower() not in ALLOWED_EXTENSIONS:
        return "bad type", 400
    f.save(os.path.join("/srv/uploads", name))
    return "ok"


def handler():
    try:
        work()
    except Exception:
        log.exception("handler failed")
        return {"error": "internal error"}, 500
