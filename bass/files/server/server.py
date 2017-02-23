import logging
import tempfile
import os
from flask import Flask, request, Response, jsonify, make_response
from cisco.bass.core import Bass
import traceback
import datetime

app = Flask(__name__)

log = logging.getLogger("cisco.bass")

bass = Bass()

@app.route("/job", methods = ["POST"])
def job_create():
    try:
        job = bass.create_job()
        return jsonify(message = "ok", job = job.json())
    except Exception as ex:
        return make_response(jsonify(message = str(ex), trace = traceback.format_exc()), 400)

@app.route("/job", methods = ["GET"])
def jobs_list():
    return jsonify(message = "ok", jobs = [j.json() for j in bass.list_jobs()])

@app.route("/job/<int:job_id>", methods = ["GET"])
def job_get_status(job_id):
    try:
        return jsonify(message = "ok", job = bass.get_job(job_id).json())
    except KeyError:
        return make_response(jsonify(message = "Invalid job id"), 400)
    except Exception as ex:
        return make_response(jsonify(message = str(ex), trace = traceback.format_exc()), 400)

@app.route("/job/<int:job_id>/add_sample", methods = ["POST"])
def job_add_sample(job_id):
    try:
        samples = []
        for name, file_ in request.files.items():
            handle, filename = tempfile.mkstemp()
            os.close(handle)
            file_.save(filename)
            samples.append(bass.get_job(job_id).add_sample(filename, name))
        return jsonify(message = "ok", samples = [s.json() for s in samples])
    except KeyError:
        log.exception("Invalid job id")
        return make_response(jsonify(message = "Invalid job id"), 400)

@app.route("/job/<int:job_id>/submit", methods = ["POST"])
def job_submit(job_id):
    try:
        bass.submit_job(job_id)
        return jsonify(message = "ok")
    except KeyError:
        return make_response(jsonify(message = "Invalid job id"), 400)

@app.route("/job/<int:job_id>", methods = ["DELETE"])
def job_delete(job_id):
    try:
        bass.delete_job(job_id)
        return jsonify(message = "ok")
    except KeyError:
        return make_response(jsonify(message = "Invalid job id"), 400)

if __name__ == "__main__":
    logging.basicConfig(filename = datetime.datetime.now().strftime("/logs/bass_%Y-%m-%d_%H-%M-%S.log"), level = logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    app.run(debug = True, host = "0.0.0.0")
    
