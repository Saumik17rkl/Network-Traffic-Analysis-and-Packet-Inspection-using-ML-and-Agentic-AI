
# Deploying CompactNetTrace Demo (Streamlit Cloud)

1. Commit the repository to GitHub.
2. Ensure model artifacts are under `artifacts/models/` and the repo size < 100 MB. If models >100MB, use Git LFS or reduce size.
3. In Streamlit Cloud (https://share.streamlit.io), create a new app, connect your GitHub repo, and set the main file to `streamlit_app.py`.
4. Use the default settings (no secrets required).
5. If app fails due to dependency versions, adjust `requirements.txt` and redeploy.

Alternative: Hugging Face Spaces (Streamlit) — similar steps; ensure `runtime.txt` if needed.

Note: Streamlit Cloud ephemeral filesystem — model files must be in the repo or downloaded during startup. For large models, host them externally and download at app start.
