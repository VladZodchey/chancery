"""A dev entrypoint for running Chancery."""

import os

from app import create_app

app = create_app(os.getenv("ENV", "development"))

if __name__ == "__main__":
    app.run(port=8888, debug=True)
