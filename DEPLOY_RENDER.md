# Deploying on Render

This project is ready for Render using the included `render.yaml`.

## What this setup does

- Creates a Python web service for the Flask app
- Starts the app with `gunicorn app:app`
- Pins Python to `3.12.8`
- Creates a free Render Postgres database
- Connects the app to Postgres through `DATABASE_URL`

## Deploy steps

1. Push this project to GitHub.
2. In Render, click `New` -> `Blueprint`.
3. Connect the repository and select this project.
4. Render will detect `render.yaml` and show:
   - Web service: `cybershield-realtime`
   - Postgres database: `cybershield-db`
5. Click `Apply`.

## Notes

- The app still supports SQLite locally.
- On Render, Postgres will be used automatically when `DATABASE_URL` is present.
- Free Render web services can sleep when inactive.
- Free Render Postgres databases are fine for testing, but plan limits still apply.

## Local run

If you want to keep using SQLite locally:

```powershell
.venv\Scripts\python.exe app.py
```

If you want to point local development at a different SQLite file:

```powershell
$env:SQLITE_PATH="E:\Major Project\CyberShield_Realtime\instance\phishing_scans.db"
.venv\Scripts\python.exe app.py
```
