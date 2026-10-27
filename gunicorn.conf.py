# Korsik video uploads go through a multipart/form-data POST.
# Large files can require more than Gunicorn's 30-second default while the
# browser sends them, before Flask parses the form or reaches S3.
# One threaded worker preserves memory while other site requests stay responsive.
worker_class = "gthread"
workers = 1
threads = 4
timeout = 600
graceful_timeout = 60
keepalive = 5

# Load checkout extensions after Gunicorn has loaded the Flask application.
# This also works when Railway overrides the Procfile and starts `gunicorn app:app`.
def post_worker_init(worker):
    import checkout_patch
    # Keep the public store wallet endpoint used by existing templates,
    # but execute the new wallet implementation.
    checkout_patch.app.view_functions['store_buy_wallet'] = checkout_patch.store_buy_wallet_v2
