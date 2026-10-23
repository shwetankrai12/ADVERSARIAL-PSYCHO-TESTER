# Demo target — practice dummy

`psycho_test_app.py` is a deliberately vulnerable single-file web app (stdlib + Pillow)
containing ~10 documented failure classes plus one genuine accidental bug. It exists so
you can run a full psycho-agents audit against a safe, owned target before pointing the
skill at your real project.

Try it:

    python3 demo/psycho_test_app.py --port 8899 --db demo.db
    # then ask: "run the psycho agents on http://localhost:8899 — it's the bundled demo app, I own it"

The `_clean` variant has the planted-bug comments stripped (the annotated original is the
answer key — read it *after* the audit to see which failure classes you actually found).

The app is self-contained; the DB file is created on first run. Nothing phones home.
