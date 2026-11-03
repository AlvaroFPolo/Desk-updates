#!/usr/bin/env python3
"""vps_update.py - authenticated, encrypted update channel for the desk (runs as root on the VPS every 10 min).

Public repo (plaintext, no secrets): latest.json + releases/v<N>.bin + this file + bootstrap.sh.
Keys are derived on each side from the APP_TOKEN (box: .secrets/app_token, VPS: /opt/desk/.secrets/app_token):
  enc  = HKDF-SHA256(app_token, salt="desk-updates/v1", info="desk-updates enc")   -> AES-256-GCM of the code tarball
  auth = HKDF-SHA256(app_token, salt="desk-updates/v1", info="desk-updates auth")  -> HMAC-SHA256 of latest.json
Flow: manifest (HMAC) -> download -> sha256 -> GCM decrypt (AAD binds the version) -> safe unpack to releases/v<N>
-> stop desk -> DB backup + settings snapshot -> copy code in place (data/, .secrets/, logs/, .venv, bin, owner.json are
never touched) -> pip only if requirements changed -> import smoke test -> start -> /api/state 401 + fresh heartbeats
+ version + DB integrity + settings unchanged -> else automatic rollback to the previous release.
Monotonic: never installs a version <= the installed one (rollback only goes back to what was installed before).
One Telegram message per update attempt. Never logs tokens or keys. Log: /opt/desk/logs/update.log.
Library use (box): release.py imports derive_keys/encrypt/sign_manifest/is_code from here."""
import ast, base64, fcntl, hashlib, hmac, io, json, os, re, shutil, sqlite3, subprocess, sys, tarfile, tempfile, time, urllib.request
from datetime import datetime

REPO = "AlvaroFPolo/Desk-updates"
SALT = b"desk-updates/v1"
INFO_ENC, INFO_AUTH = b"desk-updates enc", b"desk-updates auth"
MAX_MANIFEST, MAX_ASSET = 64 * 1024, 64 * 1024 * 1024
FILE_RE = re.compile(r"^releases/v([1-9][0-9]{0,8})\.bin$")
NOT_CODE_TOP = {"data", "logs", ".secrets", ".venv", "bin", "screens", "releases", "dist", ".git", ".pytest_cache"}
NOT_CODE_ANY = {"__pycache__"}
NOT_CODE_NAMES = {"owner.json", "desk.env", "app_token", "ngrok.yml", "bootstrap.json"}
NOT_CODE_EXT = (".pyc", ".pyo", ".pem", ".key", ".db", ".db-wal", ".db-shm", ".log", ".out", ".tgz", ".bin")


# ---------------------------------------------------------------- shared with the box (release.py)
def is_code(rel: str) -> bool:
    """rel: path relative to the desk root, '/'-separated. True = shipped by releases / replaced on update."""
    parts = rel.replace(os.sep, "/").split("/")
    if not parts or parts[0] in NOT_CODE_TOP or any(p in NOT_CODE_ANY or p in ("", ".", "..") for p in parts):
        return False
    name = parts[-1]
    return name not in NOT_CODE_NAMES and not name.endswith(NOT_CODE_EXT)


def code_files(root: str) -> list:
    out = []
    for dp, dns, fns in os.walk(root):
        rel_dp = os.path.relpath(dp, root)
        rel_dp = "" if rel_dp == "." else rel_dp.replace(os.sep, "/") + "/"
        dns[:] = sorted(d for d in dns if is_code(rel_dp + d + "/x") and not os.path.islink(os.path.join(dp, d)))
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            if is_code(rel_dp + fn) and os.path.isfile(p) and not os.path.islink(p):
                out.append(rel_dp + fn)
    return sorted(out)


def derive_keys(app_token: str):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ikm = app_token.strip().encode()
    if len(ikm) < 32:
        raise ValueError("app_token too short")
    k = lambda info: HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=info).derive(ikm)
    return k(INFO_ENC), k(INFO_AUTH)


def aad(version: int) -> bytes:
    return f"desk-release v{int(version)}".encode()


def encrypt(enc_key: bytes, version: int, plain: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return b"DSK1" + nonce + AESGCM(enc_key).encrypt(nonce, plain, aad(version))


def decrypt(enc_key: bytes, version: int, blob: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if blob[:4] != b"DSK1" or len(blob) < 4 + 12 + 16:
        raise ValueError("formato de paquete desconocido")
    return AESGCM(enc_key).decrypt(blob[4:16], blob[16:], aad(version))  # raises InvalidTag if tampered


MANIFEST_FIELDS = ("created", "file", "sha256", "size", "version")


def _canon(m: dict) -> bytes:
    return b"desk-manifest\n" + json.dumps({k: m[k] for k in MANIFEST_FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_manifest(auth_key: bytes, m: dict) -> dict:
    m = {k: m[k] for k in MANIFEST_FIELDS}
    m["hmac"] = hmac.new(auth_key, _canon(m), hashlib.sha256).hexdigest()
    return m


def verify_manifest(auth_key: bytes, m) -> dict:
    """Returns the manifest if authentic and well-formed, else raises ValueError."""
    if not isinstance(m, dict) or set(m) != set(MANIFEST_FIELDS) | {"hmac"}:
        raise ValueError("manifiesto con campos inesperados")
    want = hmac.new(auth_key, _canon(m), hashlib.sha256).hexdigest()
    if not isinstance(m["hmac"], str) or not hmac.compare_digest(want, m["hmac"]):
        raise ValueError("HMAC del manifiesto no válido")
    v = m["version"]
    fm = FILE_RE.match(str(m["file"]))
    if not isinstance(v, int) or isinstance(v, bool) or v < 1 or not fm or int(fm.group(1)) != v:
        raise ValueError("versión o fichero incoherentes")
    if not re.fullmatch(r"[0-9a-f]{64}", str(m["sha256"])) or not isinstance(m["size"], int) or not 0 < m["size"] <= MAX_ASSET:
        raise ValueError("sha256 o tamaño no válidos")
    return m


# ---------------------------------------------------------------- VPS side
CFG = {
    "desk": os.environ.get("DESK_DIR", "/opt/desk"),
    "state": os.environ.get("DESK_UPDATE_STATE", "/var/lib/desk-update"),
    "base": os.environ.get("DESK_UPDATE_BASE", f"https://raw.githubusercontent.com/{REPO}/main"),
    "api": os.environ.get("DESK_UPDATE_API", f"https://api.github.com/repos/{REPO}/contents"),
    "svc": os.environ.get("DESK_UPDATE_SVC", "systemd"),  # or a shell template with {action} (tests)
    "runas": os.environ.get("DESK_UPDATE_RUNAS", "desk"),  # "" = run as the current user (tests)
    "local": os.environ.get("DESK_LOCAL_URL", "http://127.0.0.1:" + os.environ.get("DESK_PORT", "8080")),
    "notify": os.environ.get("DESK_UPDATE_NOTIFY", "1") == "1",
    "health_s": float(os.environ.get("DESK_UPDATE_HEALTH_S", "120")),
    "self": os.environ.get("DESK_UPDATE_SELF", "/usr/local/lib/desk-update/vps_update.py"),
}


def P(*a):
    return os.path.join(CFG["desk"], *a)


def log(msg: str):
    line = f"{datetime.now().astimezone().isoformat(timespec='seconds')} {msg}"
    try:
        os.makedirs(P("logs"), exist_ok=True)
        with open(P("logs", "update.log"), "a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    if os.environ.get("DESK_UPDATE_VERBOSE") == "1" or sys.stdout.isatty():
        print(line, flush=True)


def load_state() -> dict:
    try:
        with open(os.path.join(CFG["state"], "state.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"version": 0, "failed": [], "history": []}


def save_state(st: dict):
    os.makedirs(CFG["state"], mode=0o700, exist_ok=True)
    p = os.path.join(CFG["state"], "state.json")
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(st, f, indent=1)
    os.replace(p + ".tmp", p)


def fetch(url: str, limit: int, raw_api=False) -> bytes:
    if url.startswith("file://"):
        with open(url[7:], "rb") as f:
            data = f.read(limit + 1)
    else:
        h = {"User-Agent": "desk-updater", "Cache-Control": "no-cache"}
        if raw_api:
            h["Accept"] = "application/vnd.github.raw+json"
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=60) as r:
            data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("respuesta demasiado grande")
    return data


def fetch_repo(path: str, limit: int, api_first: bool) -> bytes:
    srcs = [(CFG["base"] + "/" + path, False)]
    if CFG["api"]:
        a = (CFG["api"] + "/" + path, True)
        srcs = [a] + srcs if api_first else srcs + [a]
    err = None
    for url, raw in srcs:
        try:
            return fetch(url + ("" if raw or url.startswith("file://") else f"?t={int(time.time())}"), limit, raw)
        except Exception as e:  # urls carry no secrets
            err = e
    raise err


def run(cmd, as_desk=False, env=None, timeout=900, check=True, cwd=None):
    if as_desk and CFG["runas"]:
        cmd = ["runuser", "-u", CFG["runas"], "--"] + cmd
    r = subprocess.run(cmd, cwd=cwd or CFG["desk"], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-3:]
        name = next((os.path.basename(c) for c in cmd if not c.startswith("-") and c not in ("runuser", "--", CFG["runas"])), "?")
        raise RuntimeError(f"{name} rc={r.returncode}: {' | '.join(tail)[:300]}")
    return r


def svc(action: str, unit="desk.service"):
    if CFG["svc"] == "systemd":
        run(["systemctl", action, unit], timeout=120)
    elif unit == "desk.service":
        run(["bash", "-c", CFG["svc"].format(action=action)], timeout=120)
    if action == "stop" and unit == "desk.service":  # never swap code under a desk that is still serving
        for _ in range(30):
            if http("/api/state")[0] == 0:
                return
            time.sleep(1)
        raise RuntimeError("el desk no se ha parado (sigue respondiendo)")


def desk_env():
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": CFG["desk"], "TZ": os.environ.get("TZ", "Europe/Madrid")}


def py():
    return P(".venv", "bin", "python")


DB_PROBE = r"""
import json, sqlite3, sys
c = sqlite3.connect("data/desk.db", timeout=30)
out = {"integrity": c.execute("PRAGMA integrity_check").fetchone()[0],
       "settings": {k: v for k, v in c.execute("SELECT key, value FROM settings")}}
if len(sys.argv) > 1 and sys.argv[1] == "backup":
    d = sqlite3.connect(sys.argv[2]); c.backup(d); d.close()
if len(sys.argv) > 1 and sys.argv[1] == "restore-settings":
    want = json.loads(sys.stdin.read())
    for k, v in want.items():
        c.execute("UPDATE settings SET value=? WHERE key=?", (v, k))
    c.commit()
print(json.dumps(out))
"""


def db_probe(*args, stdin=None):
    cmd = [py(), "-c", DB_PROBE, *args]
    if CFG["runas"]:
        cmd = ["runuser", "-u", CFG["runas"], "--"] + cmd
    r = subprocess.run(cmd, cwd=CFG["desk"], env=desk_env(), input=stdin, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("comprobación de la base de datos falló: " + (r.stderr.strip().splitlines() or ["?"])[-1][:200])
    return json.loads(r.stdout.strip().splitlines()[-1])


def http(path, token=None):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(CFG["local"] + path, headers=h), timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception:
        return 0, b""


def post_check(started: float, token: str, want_version):
    """Local app 401 without token + every agent heartbeat written by the new process (< health_s) + version."""
    deadline, last = started + CFG["health_s"], "sin respuesta"
    while time.time() < deadline:
        time.sleep(3)
        s401, _ = http("/api/state")
        if s401 != 401:
            last = f"/api/state sin token -> HTTP {s401}"
            continue
        code, body = http("/api/health", token)
        if code != 200:
            last = f"/api/health -> HTTP {code}"
            continue
        try:
            h = json.loads(body)
        except ValueError:
            last = "/api/health no es JSON"; continue
        since = time.time() - started
        ages = h.get("heartbeatAgeS") or {}
        stale = [a for a, age in ages.items() if age >= since or age > 120]
        if not ages or stale:
            last = f"latidos sin renovar: {','.join(stale) or 'ninguno'}"
            continue
        if want_version and (h.get("version") or {}).get("version") != want_version:
            last = f"versión en marcha {(h.get('version') or {}).get('version')} != v{want_version}"
            continue
        return True, "ok"
    return False, last


def safe_unpack(plain: bytes, dest: str, version: int) -> dict:
    """Only regular files under code/, no links/devices/absolute/.., all listed in VERSION.json with matching sha256."""
    tmp = dest + ".part"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, mode=0o700)
    got = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.isdir():
                continue
            if not m.isfile():
                raise ValueError(f"miembro no permitido: {m.name[:80]}")
            name = m.name
            if not name.startswith("code/"):
                raise ValueError("ruta fuera de code/")
            rel = name[5:]
            if rel.startswith("/") or ".." in rel.split("/") or not is_code(rel):
                raise ValueError(f"ruta no permitida: {rel[:80]}")
            data = tar.extractfile(m).read()
            out = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as f:
                f.write(data)
            os.chmod(out, 0o755 if m.mode & 0o100 else 0o644)
            got[rel] = hashlib.sha256(data).hexdigest()
    with open(os.path.join(tmp, "VERSION.json")) as f:
        meta = json.load(f)
    if meta.get("version") != version:
        raise ValueError("VERSION.json no coincide con el manifiesto")
    files = dict(meta.get("files") or {})
    files["VERSION.json"] = got.get("VERSION.json")
    if files != got:
        raise ValueError("lista de ficheros del paquete incoherente")
    for rel in got:
        if rel.endswith(".py"):
            with open(os.path.join(tmp, rel), "rb") as f:
                ast.parse(f.read(), rel)  # syntax pre-check before touching the live desk
    shutil.rmtree(dest, ignore_errors=True)
    os.replace(tmp, dest)
    return meta


def sha_file(p):
    try:
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def apply_tree(src: str, old_files: list):
    """Copy every code file of src into the live desk (atomic per file) and delete code files that src no longer has."""
    new = code_files(src)
    for rel in new:
        dst = P(rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        tmp = dst + ".upd-tmp"
        shutil.copyfile(os.path.join(src, rel), tmp)
        os.chmod(tmp, os.stat(os.path.join(src, rel)).st_mode & 0o777)
        if CFG["runas"]:
            shutil.chown(tmp, CFG["runas"], CFG["runas"])
        os.replace(tmp, dst)
    for rel in set(old_files) - set(new):
        if is_code(rel):
            try:
                os.remove(P(rel))
            except FileNotFoundError:
                pass
    if CFG["runas"]:
        for d in {os.path.dirname(P(r)) for r in new}:
            while d.startswith(CFG["desk"] + "/") and os.path.isdir(d):
                shutil.chown(d, CFG["runas"], CFG["runas"]); d = os.path.dirname(d)
    return new


def pip_if_changed(old_dir: str, new_dir: str):
    if sha_file(os.path.join(old_dir, "requirements-vps.txt")) == sha_file(os.path.join(new_dir, "requirements-vps.txt")):
        return False
    run([P(".venv", "bin", "pip"), "install", "-q", "--no-cache-dir", "--disable-pip-version-check", "-r", P("requirements-vps.txt")],
        as_desk=True, env=desk_env(), timeout=900)
    return True


SMOKE = "import main, api, telegram, webpush, report, db, config, bootstrap; print('ok')"


def notify(text: str):
    if not CFG["notify"]:
        log(f"(aviso Telegram desactivado) {text}")
        return
    cmd = [py(), "scripts/tg_notify.py", text, "update"]
    if CFG["runas"]:
        cmd = ["runuser", "-m", "-u", CFG["runas"], "--"] + cmd
    r = subprocess.run(cmd, cwd=CFG["desk"], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    log(f"aviso Telegram: {(r.stdout or '').strip()[:60] or 'rc=' + str(r.returncode)}")


def install(m: dict, keys, st: dict, token: str) -> bool:
    enc_key, _ = keys
    N, cur = m["version"], int(st.get("version", 0))
    rel_dir = P("releases")
    os.makedirs(rel_dir, mode=0o700, exist_ok=True)
    blob = fetch_repo(m["file"], MAX_ASSET, api_first=False)
    if len(blob) != m["size"] or hashlib.sha256(blob).hexdigest() != m["sha256"]:
        raise ValueError("sha256 del paquete no coincide (descarga dañada o manipulada)")
    plain = decrypt(enc_key, N, blob)
    new_dir = os.path.join(rel_dir, f"v{N}")
    safe_unpack(plain, new_dir, N)
    prev_dir = os.path.join(rel_dir, f"v{cur}")
    if not os.path.isdir(prev_dir) or not code_files(prev_dir):  # first update: keep the migrated code as v0
        shutil.rmtree(prev_dir, ignore_errors=True)
        for rel in code_files(CFG["desk"]):
            os.makedirs(os.path.dirname(os.path.join(prev_dir, rel)), exist_ok=True)
            shutil.copy2(P(rel), os.path.join(prev_dir, rel))
    log(f"v{N}: paquete verificado y descifrado ({len(code_files(new_dir))} ficheros); instalando sobre v{cur}")

    if CFG["svc"] == "systemd":
        run(["systemctl", "stop", "desk-watch.timer"], check=False, timeout=60)
    try:
        try:
            svc("stop")
            _mkbackups()
            before = db_probe("backup", os.path.join(P("data", "backups"), f"desk-before-v{N}-{int(time.time())}.db"))
            if before["integrity"] != "ok":
                raise RuntimeError("la base de datos ya estaba dañada; no actualizo")
        except Exception:
            svc("start")  # nothing was changed: the desk goes back up on the same code
            raise
        ok, why = False, ""
        try:
            new_files = apply_tree(new_dir, code_files(prev_dir))
            pip_if_changed(prev_dir, new_dir)
            run([py(), "-c", SMOKE], as_desk=True, env=desk_env(), timeout=120)
            t0 = time.time()
            svc("start")
            ok, why = post_check(t0, token, N)
            if ok:
                after = db_probe()
                if after["integrity"] != "ok":
                    ok, why = False, "integridad de la base de datos"
                elif any(after["settings"].get(k) != v for k, v in before["settings"].items()):
                    ok, why = False, "la actualización cambió ajustes"
        except Exception as e:
            why = f"{type(e).__name__}: {str(e)[:300]}"
        if ok:
            st.update(version=N, installed_at=time.time())
            st.setdefault("history", []).append({"v": N, "ts": int(time.time()), "ok": True})
            save_state(st)
            log(f"v{N}: instalada y comprobada (app 401 sin token, 5 latidos nuevos, base de datos OK, ajustes sin cambios)")
            _self_update(new_dir)
            _prune(rel_dir, keep={N, cur})
            notify(f"Actualización v{N} instalada")
            return True
        log(f"v{N}: FALLO ({why}); vuelvo a v{cur}")
        rb_ok, rb_why = rollback(prev_dir, new_dir, before, token, cur)
        st.setdefault("failed", []).append(N)
        st.setdefault("history", []).append({"v": N, "ts": int(time.time()), "ok": False, "why": why[:200]})
        save_state(st)
        log(f"rollback a v{cur}: {'ok' if rb_ok else 'PROBLEMA: ' + rb_why}")
        notify(f"Actualización v{N} falló; vuelto a v{cur}" + ("" if rb_ok else " (el desk aún no responde; el servidor lo sigue reiniciando)"))
        return False
    finally:
        if CFG["svc"] == "systemd":
            run(["systemctl", "start", "desk-watch.timer"], check=False, timeout=60)


def _mkbackups():
    d = P("data", "backups")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    if CFG["runas"]:
        shutil.chown(d, CFG["runas"], CFG["runas"])
    olds = sorted((f for f in os.listdir(d) if f.startswith("desk-before-v")), key=lambda f: os.path.getmtime(os.path.join(d, f)))
    for f in olds[:-2]:  # keep the newest 3 (incl. the one about to be written)
        os.remove(os.path.join(d, f))


def rollback(prev_dir, new_dir, before, token, cur):
    try:
        svc("stop")
        if before:
            now = db_probe()
            diff = {k: v for k, v in before["settings"].items() if now["settings"].get(k) != v}
            if diff:
                db_probe("restore-settings", stdin=json.dumps(diff))
                log(f"rollback: restaurados {len(diff)} ajustes")
        apply_tree(prev_dir, code_files(new_dir))
        pip_if_changed(new_dir, prev_dir)
        t0 = time.time()
        svc("start")
        return post_check(t0, token, cur if cur >= 1 else None)
    except Exception as e:
        try:
            svc("start")
        except Exception:
            pass
        return False, f"{type(e).__name__}: {str(e)[:200]}"


def _self_update(new_dir):
    src = os.path.join(new_dir, "deploy", "vps_update.py")
    dst = CFG["self"]
    if dst and os.path.isfile(src) and sha_file(src) != sha_file(dst) and os.path.isdir(os.path.dirname(dst)):
        shutil.copyfile(src, dst + ".tmp"); os.chmod(dst + ".tmp", 0o755); os.replace(dst + ".tmp", dst)
        log("actualizador actualizado desde el paquete firmado")


def _prune(rel_dir, keep):
    vs = sorted(int(d[1:]) for d in os.listdir(rel_dir) if re.fullmatch(r"v\d+", d))
    for v in vs[:-3]:
        if v not in keep:
            shutil.rmtree(os.path.join(rel_dir, f"v{v}"), ignore_errors=True)


def main() -> int:
    os.makedirs(CFG["state"], mode=0o700, exist_ok=True)
    lockf = open(os.path.join(CFG["state"], "lock"), "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 0  # another run in progress
    st = load_state()
    st["last_check"] = int(time.time())
    try:
        with open(P(".secrets", "app_token")) as f:
            token = f.read().strip()
        keys = derive_keys(token)
    except Exception as e:
        log(f"sin clave: {type(e).__name__}"); return 2
    try:
        m = json.loads(fetch_repo("latest.json", MAX_MANIFEST, api_first=True))
        m = verify_manifest(keys[1], m)
    except Exception as e:
        msg = f"manifiesto rechazado o no disponible: {type(e).__name__}: {str(e)[:160]}"
        if st.get("last_err") != msg:
            log(msg)
        st["last_err"] = msg; save_state(st)
        return 3 if isinstance(e, ValueError) else 4
    st.pop("last_err", None)
    N, cur = m["version"], int(st.get("version", 0))
    if N <= cur:
        if N < cur and st.get("last_refused") != N:
            log(f"v{N} rechazada: es anterior a la instalada v{cur} (no se baja de versión)")
            st["last_refused"] = N
        save_state(st)
        return 0
    if N in st.get("failed", []):
        save_state(st)
        return 0  # already tried and rolled back; wait for a newer version
    try:
        return 0 if install(m, keys, st, token) else 5
    except Exception as e:
        log(f"v{N}: no instalada ({type(e).__name__}: {str(e)[:200]}); el desk sigue en v{cur}")
        st.setdefault("failed_tries", {})
        st["failed_tries"][str(N)] = st["failed_tries"].get(str(N), 0) + 1
        if st["failed_tries"][str(N)] >= 3:
            st.setdefault("failed", []).append(N)
            notify(f"Actualización v{N} falló; vuelto a v{cur}")
        save_state(st)
        return 6


if __name__ == "__main__":
    sys.exit(main())
