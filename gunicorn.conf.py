# Load checkout extensions after Gunicorn has loaded the Flask application.
# This also works when Railway overrides the Procfile and starts `gunicorn app:app`.
def post_worker_init(worker):
    import checkout_patch
    # Keep the public store wallet endpoint used by existing templates,
    # but execute the new wallet implementation.
    checkout_patch.app.view_functions['store_buy_wallet'] = checkout_patch.store_buy_wallet_v2
