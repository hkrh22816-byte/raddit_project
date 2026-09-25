from app import app

# Register the streamlined checkout and wallet routes after the main app
# has finished loading. Keeping this import here avoids circular-import
# issues while making the routes available to Jinja url_for() calls.
import checkout_patch  # noqa: F401,E402
