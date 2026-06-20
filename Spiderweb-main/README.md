# Spiderweb🕷️- Cybersecurity Toolkit

**Full-stack web application** with production-ready cybersecurity tools including port scanning, subdomain enumeration, PDF cryptography, hash cracking, and network discovery. Built with React + Flask.

## ✨ Features

- **Port Scanner** (`PortScannerTool.tsx`) - TCP port scanning[16]
- **Subdomain Finder** (`SubdomainTool.tsx`) - Domain enumeration[14]
- **PDF Tools** (`PdfProtectTool.tsx`, `PdfCrackTool.tsx`) - Encrypt/decrypt PDFs[15][17]
- **Hash Cracker** - Multi-format cracking
- **Network Scanner** - Local device discovery
- **Console Logs** - Real-time output (`ConsoleLog.tsx`)[12]

## 🏗️ Tech Stack

```
Frontend: React 18 + TypeScript + Tailwind + Vite (6.6k lines App.tsx) [file:53]
Backend:  Flask Python API (localhost:8000) [file:115]
Files:    2643 total (542k insertions) [file:115]
```

## 🚀 Quick Start

```bash
# Backend API (already working)
cd backend
python3 app.py
# http://localhost:8000 ✅ All endpoints 200 OK [file:115]

# Frontend Dashboard  
cd frontend
npm install
npm run dev
# http://localhost:5173
```

## 📊 Confirmed Working APIs[50]

| Endpoint | Status | Purpose |
|----------|--------|---------|
| `/api/scan/ports` | ✅ 200 | Port scanning |
| `/api/subdomain` | ✅ 200 | Subdomain enum |
| `/api/scan/network` | ✅ 200 | Network discovery |
| `/api/pdf/protect` | ✅ 200 | PDF encryption |
| `/api/pdf/crack` | ✅ 200 | PDF decryption |
| `/api/crack/hash` | ✅ 200 | Hash cracking |

## 📱 Screenshots
- Dashboard overview[19]
- Port scanner results[20]
- PDF tools interface[21][22]

## 🗂️ Project Structure

```
cybersuite-complete/          # Your monorepo [file:115]
├── backend/
│   └── app.py              # Flask API server
├── frontend/
│   ├── src/
│   │   ├── App.tsx        # 6608 lines main app [file:53]
│   │   ├── PortScannerTool.tsx  # 4218 lines [file:59]
│   │   ├── SubdomainTool.tsx    # 5560 lines [file:51]
│   │   ├── PdfCrackTool.tsx     # 5676 lines [file:58]
│   │   └── ConsoleLog.tsx       # 1414 lines [file:50]
│   ├── package.json [file:41]
│   └── vite.config.ts [file:47]
```

## 🚀 Deployment Status

✅ **Successfully force-pushed** to `https://github.com/X5464/Spiderweb.git`  
✅ **Backend live** on `localhost:8000` (all APIs tested)  
✅ **Frontend ready** (`npm run dev`)  

## 🤝 Next Steps

1. **Add `.gitignore`** (exclude `node_modules/`, `.DS_Store`)
2. **Create this README.md** 
3. **Deploy frontend** to Vercel/Netlify
4. **Deploy backend** to Railway/Render

## 📜 License
MIT License

```
SpiderWeb - Your All-in-One Cybersecurity Dashboard
Built by X5464 | Pushed Jan 12, 2026
