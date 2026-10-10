# CSF: setting up and running the project on a new computer

This guide takes you from a computer with nothing installed to the full demo running in your browser.
Follow the sections in order. Total time is about 30 to 45 minutes, most of it downloads.

## 0. What you are about to run

CSF is a security gateway: a "guard" that sits in front of a website and inspects every request before the
website sees it. The demo has three parts:

| Part | What it is | How it runs |
|---|---|---|
| **The guard** | The gateway (Python), the rules engine (Go + OWASP rules), a deliberately vulnerable sample shop, and a helper API for the dashboard | In **Docker**, in the background |
| **The dashboard** | The website with the pages you present | **Node.js**, in a terminal window |
| **Docker Desktop** | The program that runs the guard | You start it yourself |

You do **not** need to install Python, Go or any database. Docker builds and runs all of that for you.

## 1. Check your computer

- Windows 10 or 11 (64-bit), macOS, or Linux.
- At least **8 GB RAM** (Docker uses 1 to 3 GB while running).
- About **10 GB free disk space** (Docker images and build cache).
- **Virtualisation enabled** (it is on by default on most laptops; see Troubleshooting if Docker complains).
- An internet connection for the first setup (about 2 GB of downloads).
- Administrator rights, to install Docker Desktop.

## 2. Install the prerequisites

### 2.1 Git

Git downloads the project.

1. Go to https://git-scm.com/downloads and download the installer for your system.
2. Run it and click **Next** through every screen (the defaults are fine).
3. Open a **new** terminal (on Windows: press the Windows key, type `PowerShell`, press Enter) and check:
   ```
   git --version
   ```
   You should see something like `git version 2.4x.x`.

### 2.2 Node.js (version 20 or newer)

Node.js runs the dashboard website.

1. Go to https://nodejs.org and download the **LTS** version.
2. Run the installer with the defaults. If it offers to install extra "tools for native modules", you can leave that unticked.
3. Close and reopen your terminal, then check:
   ```
   node -v
   npm -v
   ```
   `node -v` must show `v20` or higher.

### 2.3 Docker Desktop

Docker Desktop runs the guard.

1. Go to https://www.docker.com/products/docker-desktop and download Docker Desktop for your system.
   It is free for personal and educational use.
2. Run the installer. On Windows, keep **"Use WSL 2 instead of Hyper-V"** ticked.
3. When the installer finishes, **restart your computer** if it asks.
4. Open **Docker Desktop** from the Start menu. Accept the licence agreement. You can skip signing in and skip the survey.
5. Wait until the bottom-left shows **"Engine running"** (green). This takes 1 to 2 minutes the first time.
6. Check in a terminal:
   ```
   docker --version
   docker compose version
   ```
   Both must print a version.

Optional, only if you want to run the backend tests yourself: install **uv** (https://docs.astral.sh/uv/) which
manages Python for you. The demo itself does not need it.

## 3. Download the project

Open a terminal, go to the folder where you keep projects, and run:

```
git clone https://github.com/JINAYSHAH-888/csf
cd csf
```

You should now be inside a folder that contains `backend`, `frontend`, `console-api`, `run-demo.bat`,
`DEMO.md` and `SETUP.md`.

## 4. Add the attack rules (one-time step)

The OWASP rule set used by the rules engine is too large to store in git, so it is **not** in the download.
You must add it yourself. Choose either method.

**Method A: download it (needs internet):**
```
git clone --depth 1 --branch v4.21.0 https://github.com/coreruleset/coreruleset vendor/crs
```

**Method B: copy it from the shared `csf.zip`:** unzip it and copy its `vendor` folder into the project folder,
next to `backend` and `frontend`.

Check it worked: the folder `vendor/crs/rules` must exist and contain `.conf` files. If it does not, the next
step will refuse to start and tell you so.

## 5. Start everything

1. Make sure **Docker Desktop is open and says "Engine running"**.
2. **Windows:** double-click `run-demo.bat` in the project folder.

   **macOS or Linux:** run these in two terminals:
   ```
   docker compose -f console-api/compose.yaml up -d --build
   ```
   ```
   cd frontend && npm install && npm run dev
   ```

What you will see:
- A terminal window builds and starts the guard in Docker. **The very first run takes 5 to 10 minutes**
  because Docker downloads and builds everything. Later runs take seconds. It ends with lines such as
  `Container ... Started`.
- A second window, "CSF frontend", installs the website packages and prints
  `Local: http://localhost:5173/`.
  **Keep this window open.** Closing it stops the website.

## 6. Open the dashboard and check it works

1. Open **http://localhost:5173** in Chrome or Edge.
2. Top-right of the page should say **Online** (green) and **Enforce** (red, highlighted).
3. Quick test: open **Threat simulator**, click **SQL injection**, then **UNION exfiltration**.
   You should see a red **"Blocked by the gateway"**.
4. In Docker Desktop, under **Containers**, `csf-console` should have a green dot and two containers inside,
   `console` and `s1`.

If all of that is true, everything is working. See `DEMO.md` for what each page shows and how to present it.

Ports used (they must be free): **5173** (website), **8000** (dashboard helper API), **8080** (the guard, HTTPS).

## 7. Stopping and starting again

| Goal | What to do |
|---|---|
| Pause for now | Close the "CSF frontend" window, then quit Docker Desktop |
| Stop the guard fully | `docker compose -f console-api/compose.yaml down` |
| Start again later | Open Docker Desktop, wait for "Engine running", then run `run-demo.bat` again (fast the second time) |
| Free disk space after the project is finished | `docker compose -f console-api/compose.yaml down -v --rmi all`, then `docker builder prune` |

## 8. Troubleshooting

| What you see | Why | Fix |
|---|---|---|
| Top-right says **Offline** | The guard is not running | Start Docker Desktop, wait for "Engine running", re-run `run-demo.bat` |
| `docker` is not recognised, or "cannot connect to the Docker daemon" | Docker Desktop is closed or still starting | Open Docker Desktop and wait for "Engine running" |
| `vendor\crs is missing` | Step 4 was skipped | Do step 4 |
| Docker says virtualisation is disabled or WSL 2 is missing | Virtualisation is off in the BIOS, or WSL is not installed | Run `wsl --install` in an administrator PowerShell and restart. If it persists, enable "Virtualization Technology" in the BIOS |
| Website opens on **5174** instead of 5173 | An older copy of the website is still running | Close the old "CSF frontend" window, or use the address it printed |
| "Port is already allocated" or "port in use" | Another program (or an old copy of the project) holds 5173, 8000 or 8080 | Run `docker compose -f console-api/compose.yaml down`, close old terminals, or restart the computer |
| The pipeline shows S1 as offline | The rules container is not healthy | Check `s1` is green in Docker Desktop, then re-run `run-demo.bat` |
| `npm install` fails | Node is too old or the network blocked it | Check `node -v` is 20 or higher, then retry |
| First start is very slow | Docker is downloading and building | Wait. This only happens once |
| Numbers on the dashboard look messy | Leftover test data | Open **Live traffic** and click **Clear log** |
| Windows Firewall asks about Docker or Node | Normal | Allow on private networks |

## 9. Where things are

| Folder or file | What it holds |
|---|---|
| `backend/` | The gateway (Python): TLS-ready proxy, JWT checks, semantic analysis, decision engine, tests |
| `s1-sidecar/` | The rules engine (Go): Coraza running the OWASP rules |
| `console-api/` | The dashboard helper API and the Docker setup that runs everything (`compose.yaml`) |
| `frontend/` | The dashboard website (React) |
| `docs/` | Design notes (ADRs), benchmark results, threat model, runbook |
| `deployment/` | Kubernetes files from the backend team |
| `DEMO.md` | What each page shows and how the project maps to the project proposal |
| `vendor/crs/` | The OWASP rules you added in step 4 (not in git) |

Teammates: work on your own branch (`git checkout -b yourname`) rather than committing straight to `main`.

## 10. Why this cannot be hosted on Vercel

Vercel is excellent for websites, but it is the wrong kind of platform for this project's guard. In short:
**Vercel can host the dashboard, but not the guard that the dashboard displays.**

What Vercel is: a host for static sites plus **serverless functions**. A serverless function wakes up for a single
request, runs for a few seconds, forgets everything, and shuts down. You cannot install your own programs, run
Docker containers, or keep anything running in the background.

What our guard needs, and why that does not fit:

1. **It must run continuously.** The guard is a long-running server. It remembers how many attacks it has blocked
   recently, tracks rate limits, runs a circuit breaker, and checks for alerts every 2 seconds. A serverless
   function loses all of that state after every request.
2. **It is two programs working together.** The Python gateway talks to the Go rules engine over a **Unix socket
   shared between two containers**. Vercel cannot run containers or share sockets between processes.
3. **It is a proxy by design.** The whole point is to sit *in front of* an application and inspect traffic before
   it arrives. Vercel decides how requests reach its functions. You cannot place our guard in that path, and the
   guard needs to reach its own upstream (the sample shop) over the network.
4. **TLS is the guard's job here.** Our gateway terminates HTTPS itself. On Vercel, Vercel terminates TLS before
   anything of ours runs, so that part of the project would not be ours to demonstrate.
5. **It needs custom software.** The rules engine is a compiled Go program and the attack rules are loaded from
   disk. Vercel does not allow installing those.

What can work:
- **The dashboard alone can go on Vercel**, because it is an ordinary Vite site. But on its own it shows
  "Offline", since nothing is behind it.
- **To have it online:** run the Docker stack on a small cloud server (a virtual machine you control, with Docker
  installed), put HTTPS in front of it with a tool like Caddy, host the dashboard on Vercel, and point the
  dashboard at the server with the `VITE_API` setting. Two cautions: the dashboard helper API can send arbitrary
  requests and switch modes, so it must be password-protected if it is exposed to the internet, and the browser
  only allows an HTTPS site (Vercel) to call an HTTPS API.

For a project presentation, running everything on a laptop (as in this guide) is simpler and more reliable than
hosting it.
