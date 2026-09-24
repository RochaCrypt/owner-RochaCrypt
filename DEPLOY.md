# AI Assistant Site — deploy on Vercel

Your landing page + a secure AI terminal. The NVIDIA API key stays server-side
(a Vercel environment variable) and is never exposed to visitors.

## Files
- `index.html` — the site, including the AI terminal (calls `/api/chat`)
- `api/chat.js` — serverless proxy to NVIDIA (build.nvidia.com), OpenAI-compatible

## Deploy (5 minutes)

1. Put these files in a new GitHub repo (e.g. `RochaCrypt/site` or `RochaCrypt.github.io`).
2. Go to **vercel.com** → **Add New → Project** → import that repo.
3. Framework preset: **Other**. Root directory: default. Click **Deploy**.
4. After the first deploy, open **Project → Settings → Environment Variables** and add:

   | Name | Value |
   | :-- | :-- |
   | `NVIDIA_API_KEY` | your `nvapi-...` key from build.nvidia.com |
   | `NVIDIA_MODEL` | *(optional)* e.g. `meta/llama-3.1-8b-instruct` to save credits |

5. **Redeploy** (Deployments → ⋯ → Redeploy) so the new env var is picked up.
6. Open your Vercel URL — the AI terminal on the page will answer questions.

## Point your profile at it
- In `RochaCrypt/RochaCrypt` README and in **Edit profile → Website**, use the Vercel URL.

## Protect your credits (recommended before sharing widely)
The proxy already caps history and message length. For a public bot, also add:
- **Rate limiting** with Upstash Redis (`@upstash/ratelimit`) keyed by IP.
- A **smaller model** (`meta/llama-3.1-8b-instruct`) via `NVIDIA_MODEL` for speed and lower cost.
- Vercel's built-in **Firewall / attack challenge** for abusive traffic.

## Choosing a model
Any chat model listed on build.nvidia.com works. Good options:
`meta/llama-3.1-70b-instruct` (quality) · `meta/llama-3.1-8b-instruct` (fast/cheap) ·
`nvidia/llama-3.1-nemotron-70b-instruct`.
