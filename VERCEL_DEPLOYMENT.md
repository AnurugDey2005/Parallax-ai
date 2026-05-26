# Parallax Vercel Frontend Setup

This frontend is static and can run on Vercel Hobby without adding payment details, as long as usage stays within the free tier.

## Files to Prepare

1. Copy `config.example.js` to `config.js`.
2. Set `apiBase` to the Render backend URL.
3. Set `googleClientId` to the Google OAuth Web Client ID.
4. Keep secrets out of `config.js`; it is browser-visible.

## Vercel Settings

- Framework preset: Other
- Root directory: `frontend`
- Build command: leave empty
- Output directory: `.`
- Install command: leave empty

## Google OAuth Settings

In Google Cloud Console, add the Vercel production URL to Authorized JavaScript origins.

Example:

```text
https://your-parallax-frontend.vercel.app
```

## Free-Tier Notes

- Vercel Hobby is free for personal/non-commercial projects within its usage limits.
- For public launch with many users, monitor usage carefully before adding billing.
- Submit the final domain to Google Search Console after deployment so Google can index it.
