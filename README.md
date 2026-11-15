# safe

Keep media folders (courses, recordings, shows you own) in a private Cloudflare R2 bucket, and watch or download
them from a small password-protected web page. One Python script, one Worker, one HTML file.

- R2 has no egress fees, so streaming and downloading cost nothing. Storage is $0.015/GB-month after the first 10 GB.
- Videos that browsers can play (8-bit H.264 with AAC/MP3) are streamed. MKVs with those codecs are repackaged to
  MP4 without re-encoding. Everything else is offered as a download.
- Every upload is read back from the bucket, and a resource only counts as verified against a fresh bucket listing,
  so you know when it is safe to delete the local copy.

## How it fits together

| File | Role |
|---|---|
| `safe` | CLI: scans folders, converts where needed, uploads, verifies, writes `manifest.json` and `ARCHIVE.md` |
| `worker.js` | Cloudflare Worker: serves the bucket behind a password, with range requests for seeking |
| `index.html` | The site: library grid, then a player with the lesson list beside it. Reads `manifest.json` |
| `resources.json` | Your list of folders, one "resource" each (not committed) |
| `config.json` | Your bucket name and R2 endpoint (not committed) |

## Setup

Needs macOS, Python 3.9+, `ffmpeg`, the `aws` CLI and Node (for `npx wrangler`).

1. Create a bucket and deploy the Worker (edit `bucket_name` in `wrangler.toml` first):

   ```
   npx wrangler r2 bucket create my-bucket
   npx wrangler deploy
   npx wrangler secret put PASSWORD
   npx wrangler secret put SESSION_KEY     # any long random string; signs the login cookie
   ```

2. Copy `config.example.json` to `config.json` and fill in the bucket and your endpoint
   (`https://<account-id>.r2.cloudflarestorage.com`).

3. In the Cloudflare dashboard create an R2 API token (Object Read & Write, that bucket only) and store it in the
   keychain. Each command prompts for the value:

   ```
   security add-generic-password -U -s safe-r2 -a access-key-id -w
   security add-generic-password -U -s safe-r2 -a secret-access-key -w
   ```

   For the secret you can paste either the S3 secret access key or the raw API token value.

## Use

```
./safe add ~/Downloads/"Some Course"     track a folder or file as its own resource
./safe ls                                what is tracked, sizes, how much is uploaded and verified
./safe push [id...] [--jobs N]           upload (smallest remaining first), verify, refresh the site
./safe check <id>                        health check: every file present, every video opens with the right length
./safe pull <id> [dest]                  download a resource back
./safe rm <id> [--purge]                 stop tracking; --purge also deletes it from the bucket
```

`push` can be stopped and re-run; it skips what is already in the bucket and retries through network drops.
After a resource shows `verified` and passes `check`, you can delete the local folder: the resource stays on the
site, because its record is kept in `manifest.json`.

`ARCHIVE.md` is generated next to the manifest and uploaded with it. It lists, per resource, the original folder
name, where it came from (the `source` field in `resources.json`), and magnet links for any `.torrent` files found
inside, so you can find things again if the bucket is ever lost.

## Limits

- Single user. Logins last 30 days; changing `PASSWORD` or `SESSION_KEY` logs every browser out.
- Login attempts are rate-limited per client address (about 5 a minute; Cloudflare's limiter is approximate).
- Only video, audio, common images, subtitles and PDFs are shown in the browser. Every other file in the bucket is
  sent as a download, so an HTML file inside an uploaded folder cannot run on the site.
- Watched state and resume positions live in the browser's `localStorage`, per device.
- The keychain lookup is macOS-only.
- Only store files you have the right to keep.
