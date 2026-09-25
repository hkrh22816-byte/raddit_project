# Load checkout extensions after Gunicorn has loaded the Flask application.
# This also works when Railway overrides the Procfile and starts `gunicorn app:app`.
def post_worker_init(worker):
    import checkout_patch  # noqa: F401
