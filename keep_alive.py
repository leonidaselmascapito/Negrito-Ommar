from flask import Flask
from threading import Thread
import os

app = Flask(__name__)

@app.route("/")
def home():
    return "Discord moderation bot is running.", 200

@app.route("/health")
def health():
    return {"status": "ok"}, 200


def _run():
    port = int(os.environ.get("PORT", 10000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        use_reloader=False
    )


def keep_alive():
    thread = Thread(target=_run, daemon=True)
    thread.start()
