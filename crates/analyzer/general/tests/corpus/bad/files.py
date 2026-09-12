# EXPECT: gen_toctou_file
# EXPECT: gen_insecure_temp_file
# EXPECT: gen_insecure_file_permissions
# EXPECT: gen_xxe
# EXPECT: gen_upload_unvalidated
# EXPECT: gen_error_detail_exposed
import os, tempfile
from lxml import etree
from flask import request, jsonify


def read_if_present(path):
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read()


def scratch():
    name = tempfile.mktemp()
    os.chmod(name, 0o777)
    return name


def parse_xml():
    return etree.fromstring(request.data)


def upload():
    f = request.files["doc"]
    f.save(os.path.join("/srv/uploads", f.filename))
    return "ok"


def handler():
    try:
        work()
    except Exception as e:
        return jsonify(error=str(e)), 500
