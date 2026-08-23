# CloudPaste - Online Clipboard Text & File Sharing Platform
# Cloudflare Worker Text & File Sharing Platform
> A lightweight self‑hosted sharing service built on Cloudflare Worker + KV + R2. Supports text (Markdown / LaTeX formula) and file sharing, password protection, expiration time, access‑count limits, and an admin dashboard. Runs entirely on Cloudflare edge network with no origin server required.

## ✨ Features
### 📝 Text Sharing
- Real‑time Markdown preview with GFM syntax support
- Code syntax highlighting (highlight.js)
- LaTeX math formula rendering (KaTeX)
- Password‑protected shares
- Configurable expiration time and maximum access count
- Custom share ID suffix
- Edit text content from admin dashboard

### 📁 File Sharing
- Drag‑and‑drop upload, multi‑file simultaneous upload
- Max single file size **98 MB** (Worker hard limit)
- In‑browser preview for images / PDF / audio / video
- Password protection and expiration time
- Maximum access count & maximum download count limits
- Custom share ID
- File binaries stored in R2 object storage; metadata stored in KV

### 🔐 Admin Dashboard
- Admin password login, 7‑day session validity
- Toggle text / file upload functionality
- View full share list and storage statistics
- Modify share password, access / download limits
- Rename share link (change share ID)
- Delete shares (associated R2 files are removed as well)
- Update admin password

### 🛠 Additional Capabilities
- PWA support, Service Worker for static CDN resource caching
- Dark / light theme switch
- Auto expiration cleanup (recycle expired or access‑limit‑reached shares)
- Simple clipboard API (`/save` `/read` `/clear`)
- Path prefix TOKEN for sub‑path deployment
- Global error catching, JSON‑formatted errors for debugging

## 🧱 Deployment Dependencies
> All resources are Cloudflare serverless, **no VPS required**
1. **Cloudflare Worker**: Executes JavaScript logic
2. **KV Namespace**: Stores share metadata, configurations, admin sessions and statistics
3. **R2 Bucket**: Stores uploaded file binary data

## 📦 Environment Variables (Worker Variables)
| Variable Name | Description | Required |
|---|---|---|
| `ADMIN_PASSWORD` | Plain‑text admin password. Hashed and saved into KV on first run. This variable can be removed afterwards. | ✅ |
| `TOKEN` | Optional path prefix. Example: `abc123` → access URL becomes `your‑domain/abc123/` | ❌ |
| `EXPIRE` | Default text expiration in seconds. `0` = permanent. Default value: `300` (5 minutes). | ❌ |

### Bindings (Names must match exactly)
| Type | Variable Name | Description |
|---|---|---|
| KV Namespace | `KV` | KV storage binding |
| R2 Bucket | `R2` | R2 object‑storage bucket binding |

> ⚠️ Notice: Binding variable names **must be uppercase `KV` and `R2`**. Hard‑coded in source code and cannot be customized.

## 🚀 Deployment Steps
1. Go to Cloudflare Console → Workers & Pages → Create Worker
2. Paste the full JavaScript source code into the Worker editor and deploy
3. Create a KV Namespace. In Worker Settings → Bindings bind KV with variable name: `KV`
4. Create an R2 Bucket. In Worker Settings → R2 Object Storage bind bucket with variable name: `R2`
5. Set environment variable `ADMIN_PASSWORD` with your desired admin password
6. (Optional) Configure `TOKEN` and `EXPIRE` environment variables
7. Visit your Worker domain to open the main web page
8. After first visit, `ADMIN_PASSWORD` will be hashed and persisted inside KV. You may delete the plain‑text environment variable to avoid credential leakage.

> Admin panel URL: `https://your‑worker‑domain/admin`

## 📝 Usage Instructions
### Regular Users
1. **Text Share**: Write Markdown content with live preview. Configure password, expiration time, access limit and custom share ID, then generate share link.
2. **File Share**: Drag‑and‑drop or select local files, set parameters and upload to generate share link.
3. Access shares via share ID, subject to password, expiration and access‑count restrictions.

### Administrator Operations
1. Navigate to `/admin` and log in with admin password
2. View storage statistics; enable or disable text / file upload features
3. Browse all shares; modify password, count limits, rename share ID or delete shares
4. Change administrator login password

## ⚠️ Important Limitations
1. Worker request payload hard limit: **100 MB**, practical single‑file limit **98 MB**. Cannot be bypassed.
2. R2 free tier quota: 10 GB storage per month, 1 million read requests. Costs may be incurred once quota is exceeded. Monitor your usage.
3. KV free tier has limited read‑write capacity. Suitable for personal use; not for high‑traffic public services.
4. Auto cleanup is **request‑triggered**, not real cron job. Cleanup runs only when Worker receives requests, at most once per hour.
5. Do not expose this service to large public audiences. This project targets personal and small‑group scenarios.

## 🔗 API Reference
> Base path: `[TOKEN‑prefix]/api`

| Endpoint | Method | Description |
|---|---|---|
| `/api/admin/login` | POST | Admin login, obtain session token |
| `/api/admin/logout` | POST | Admin logout |
| `/api/admin/config` | GET / PUT | Get / update system configuration |
| `/api/admin/stats` | GET | Retrieve storage statistics |
| `/api/admin/shares` | GET | List all shares |
| `/api/share/text` | POST | Create text share |
| `/api/share/file` | POST | Create metadata record for file share |
| `/api/upload/{shareId}/{index}` | PUT | Upload individual file binary to R2 |
| `/api/share/{id}` | GET | Get share metadata (password validation applied) |
| `/api/share/{id}/verify` | POST | Verify share access password |
| `/api/share/{id}/file/{index}` | GET | File download / preview |
| `/api/share/{id}/delete` | POST | Delete share (admin only) |
| `/api/share/{id}/password` | PUT | Update share password (admin only) |
| `/api/share/{id}/limits` | PUT | Modify access / download count limits (admin only) |
| `/api/share/{id}/rename` | PUT | Rename share ID (admin only) |
| `/api/share/{id}/edit` | PUT | Edit text‑share content (admin only) |

## 📄 Simple Clipboard API
- `POST /save`: Save text content to KV clipboard
- `GET /read`: Read clipboard content
- `GET /clear`: Clear clipboard content

## 🛡️ Security Notes
1. **Always set a strong admin password**. Avoid weak passwords.
2. Remove plain‑text `ADMIN_PASSWORD` environment variable after first deployment. Credential is stored as hash inside KV.
3. Do not open service to anonymous mass users to prevent unexpected R2 / KV billing charges.
4. Share passwords are application‑layer protection only. Files are stored unencrypted in R2. Encrypt sensitive files locally before uploading.
5. This project is for personal learning purposes. Direct production‑grade commercial usage is not recommended.

## 📃 License
> MIT License, for personal study only.
