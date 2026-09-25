from app import app

# Register checkout and wallet routes only after the main app is fully loaded.
# This avoids circular imports and guarantees Jinja can resolve the new endpoints.
import checkout_patch  # noqa: F401,E402

# Keep the public endpoint already used by templates, but execute the
# real wallet implementation from checkout_patch.
app.view_functions['store_buy_wallet'] = checkout_patch.store_buy_wallet_v2
