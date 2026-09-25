# Ensure checkout/payment route extensions are registered no matter how Gunicorn starts the app.
import checkout_patch as _checkout_patch

# Keep the public endpoint name used by the store template, but route it to
# the real wallet implementation from checkout_patch.
_checkout_patch.app.view_functions['store_buy_wallet'] = _checkout_patch.store_buy_wallet_v2
