# IPIntel Cloudflare Worker

Behavior-based bot protection at the Cloudflare edge using IPIntel.ai.
Helps to stop fake traffic, bot noise, polluted analytics.

This Worker evaluates incoming requests **before they reach your origin** and applies
real-time decisions: **Allow**, **Challenge**, or **Block**.

## How it works

1. Request arrives at Cloudflare
2. Worker evaluates IP behavior via IPIntel.ai
3. Decision applied at the edge
4. Challenged users are redirected to a custom verification page
5. Verified users receive a short-lived cookie and bypass future challenges

## Requirements

- Cloudflare account with Workers enabled
- Any website behind Cloudflare
- IPIntel.ai API key (obtain from https://ipintel.ai)

## Installation

1. Create a new Worker in Cloudflare Dashboard
2. Copy `worker.js` into the editor
3. Go to Settings -> Variables and Secrets and add new variable:
   - Type: Secret
   - Variable name: IPINTEL_API_KEY
   - Value: Your api key
5. Attach the Worker to your route (Create the route from Workers Routes)
6. Deploy

## Privacy

- No tracking scripts
- No fingerprinting
- No persistent identifiers
- Short-lived cookie used only after successful challenge

## Disclaimer

Cloudflare is a trademark of Cloudflare, Inc.  
IPIntel.ai is an independent product and is not affiliated with or endorsed by Cloudflare.
