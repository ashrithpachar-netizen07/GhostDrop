# 👻 Ghostdrop — one-off file transfer that vanishes
Express + SQLite + vanilla JS. **Run:** `npm i && npm start` → http://localhost:3000 · **Test:** `npm test`

## Users & scope
Owner (logged in): upload, create links, see download counts, revoke, delete. Recipient: no account, just opens the link (password if set).
Out of scope: previews, folders, sharing between accounts, email delivery.

## File rules (all enforced server-side)
10 MB/file · 50 MB & 50 files/user · 20 links/file · expiry 1h–7d · optional max downloads (burn-after-N) · optional link password.
Blocked: executable/script/HTML/SVG extensions AND files whose *content* (magic bytes) is an executable, script or HTML — even if renamed `.txt`.

## Architecture
Browser SPA → Express API → **Turso** (hosted SQLite, persistent): users, link metadata *and* file bytes (BLOB). No local disk is needed, so it survives restarts, redeploys and free-tier hosts.
Upload: auth → multer (memory, hard 10 MB cap) → type/magic-byte/quota checks → DB row. Download: hash lookup → state check → password → atomic counter → send.

## Security
- 192-bit random tokens; only SHA-256 hash stored (shown once)
- Atomic SQL download counter (no race past the limit)
- Uploads served as `application/octet-stream` + `attachment` + `nosniff`, never written to a web-served path → can't execute in a browser
- bcrypt for passwords; httpOnly + SameSite=Strict cookie; CSRF header check on all API writes; helmet CSP
- Rate limits; login lockout (5 fails → 15 min); per-link password brute-force lockout; constant-time-ish login (no user enumeration)
- Ownership check on every owner route (other users get 404); UI output escaped; `X-Robots-Tag: noindex` on links
- Orphaned uploads purged hourly
- **Email verification:** accounts stay inactive until the emailed link (24 h, single-use, hash-stored) is confirmed; confirm is a button+POST so mail scanners can't consume it; unverified accounts can be re-claimed by the real owner and are purged after 24 h; resend has a cooldown and a generic response (no enumeration)
- Clear 404/410 messages: expired, revoked, limit reached, deleted

## Deploy (100% free, no card)
1. **Turso:** sign up at turso.tech → create database → copy its URL (`libsql://…`) and create an auth token.
2. **Render:** New → Web Service → connect GitHub repo → Runtime Node, Build `npm ci`, Start `npm start`, Instance **Free**.
3. Env vars: `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `JWT_SECRET=<long random>`, `NODE_ENV=production`.
4. Free Render sleeps after ~15 min idle (first load ~30–60 s). Optional: free UptimeRobot ping on `/healthz` every 5 min.

### Email verification setup (free)
Brevo → Senders & IP → add + verify a sender email → SMTP & API → create an **API key**. Render env vars: `BREVO_API_KEY`, `MAIL_FROM` (the verified sender). Uses Brevo's HTTPS API because free Render blocks SMTP ports. Without these vars, production sign-up fails safely; locally the link is printed to the console.

Live URL: _add here_
