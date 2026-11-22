# Tish's Kitchen admin

Tish's order counter and money app. Lives at https://admin.tishxkitchen.com.
The customer ordering site is in the `tishs-kitchen` repo at https://tishxkitchen.com.

Single `index.html`, no build step. Data is stored on the phone (localStorage).
On first open it copies data from the old address through `tishxkitchen.com/bridge.html`.

## Online orders

Orders placed on tishxkitchen.com come in from the order API in `backend/`
(Cloudflare Worker + D1 at api.tishxkitchen.com). See `backend/README.md`.
The phone connects once through a setup link `admin.tishxkitchen.com/#key=...`,
then More, Turn on notifications. `sw.js` only shows notifications, it caches nothing.
