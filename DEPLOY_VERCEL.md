# Deploying on Vercel

This project can run on Vercel from `app.py`.

## Important note about data

- If `DATABASE_URL` is set, the app will use that database.
- If `DATABASE_URL` is not set on Vercel, the app falls back to `/tmp/phishing_scans.db`.
- `/tmp` is temporary on Vercel, so scan history will not be durable there.

## Static files

Vercel serves static assets from `public/**`.
This project keeps local Flask assets in `static/` and deployable Vercel assets in `public/static/`.

## Deploy steps

1. Push the latest code to GitHub.
2. In Vercel, import the repository.
3. Add `DATABASE_URL` in the Vercel project settings if you want persistent history.
4. Deploy.

## If you are moving off Render

- You can stop or delete the Render web service after Vercel is working.
- Do not delete the Render Postgres database unless you have moved `DATABASE_URL` to another provider.
