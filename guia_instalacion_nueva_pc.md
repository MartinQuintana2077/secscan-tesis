# Installation Guide — SecScan

## Prerequisites

Make sure the following tools are installed before proceeding:

- **Git** — [Download here](https://git-scm.com/)
- **Python 3.10+** — [Download here](https://www.python.org/). During installation, check **"Add Python to PATH"**
- **Node.js v18+** — [Download here](https://nodejs.org/)
- **Nmap** — The app can install it automatically on first launch

---

## 1. Clone the repository

```powershell
git clone https://github.com/MartinQuintanaC/secscan-tesis.git
cd secscan-tesis
```

---

## 2. Configure the Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

> **Firebase credentials:** The `firebase_admin.json` file is **not included** in the repository for security reasons.  
> You must obtain it from your Firebase project console (Project Settings → Service Accounts → Generate new private key) and place it inside the `backend/` folder.

---

## 3. Configure the Frontend

```powershell
cd frontend
npm install
```

---

## 4. Start the application

**Option A — Windows (one click):**
```
iniciar_secscan.bat
```

**Option B — Manual (two terminals):**

Terminal 1:
```powershell
cd backend
.\venv\Scripts\activate
uvicorn app:app --reload
```

Terminal 2:
```powershell
cd frontend
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 5. Install Nmap (first time only)

If Nmap is not detected, the dashboard will show a warning banner with an **"Install Automatically"** button. Click it and SecScan will handle the installation.

---

## Daily usage

Once everything is set up, just run:
```powershell
# Terminal 1
cd backend; .\venv\Scripts\activate; uvicorn app:app --reload

# Terminal 2
cd frontend; npm run dev
```
