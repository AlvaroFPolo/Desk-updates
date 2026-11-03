#!/usr/bin/env bash
# Canal de actualizaciones del desk: instala el actualizador y su temporizador (cada 10 min) en el servidor.
# Sin secretos: la clave se deriva en el propio servidor de /opt/desk/.secrets/app_token.
# Uso (como root):  curl -fsSL https://raw.githubusercontent.com/AlvaroFPolo/Desk-updates/main/bootstrap.sh | bash
# Todo va dentro de main() para que bash lo lea entero antes de ejecutar nada.
set -Eeuo pipefail

main() {
  local R="https://raw.githubusercontent.com/AlvaroFPolo/Desk-updates/main" L=/usr/local/lib/desk-update
  export DEBIAN_FRONTEND=noninteractive
  trap 'echo; echo "ERROR: no se ha completado. El desk sigue funcionando igual que antes (PAPER)."' ERR
  [ "$(id -u)" = 0 ] || { echo "Ejecuta esto como root."; exit 1; }
  if [ ! -s /opt/desk/.secrets/app_token ] || ! systemctl cat desk.service >/dev/null 2>&1; then
    echo "No encuentro el desk en /opt/desk en este servidor."; exit 1
  fi
  echo "== Canal de actualizaciones del desk =="

  echo "1/4 Instalando lo necesario..."
  if ! /usr/bin/python3 -c "import cryptography.hazmat.primitives.ciphers.aead" 2>/dev/null; then
    apt-get update -qq </dev/null
    apt-get install -y -qq python3-cryptography </dev/null >/dev/null
  fi
  /usr/bin/python3 -c "import cryptography.hazmat.primitives.ciphers.aead, cryptography.hazmat.primitives.kdf.hkdf"

  echo "2/4 Descargando el actualizador..."
  install -d -m 755 -o root -g root "$L"
  curl -fsSL -m 60 --retry 3 -o "$L/vps_update.py.part" "$R/vps_update.py?t=$(date +%s)" </dev/null
  /usr/bin/python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$L/vps_update.py.part"
  chmod 755 "$L/vps_update.py.part"; mv -f "$L/vps_update.py.part" "$L/vps_update.py"

  echo "3/4 Creando el temporizador (busca actualizaciones cada 10 minutos)..."
  cat >/etc/systemd/system/desk-update.service <<'UNIT'
[Unit]
Description=Actualizaciones firmadas y cifradas del desk
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/desk/desk.env
ExecStart=/usr/bin/python3 /usr/local/lib/desk-update/vps_update.py
TimeoutStartSec=20min
Nice=5
UNIT
  cat >/etc/systemd/system/desk-update.timer <<'UNIT'
[Unit]
Description=Busca actualizaciones del desk cada 10 minutos

[Timer]
OnBootSec=4min
OnUnitActiveSec=10min
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload </dev/null
  systemctl enable desk-update.timer </dev/null >/dev/null 2>&1

  echo "4/4 Instalando la primera actualización (1-3 minutos, el desk se reinicia un momento)..."
  trap - ERR
  systemctl start desk-update.service </dev/null || true
  systemctl start desk-update.timer </dev/null || true
  local v
  v=$(/usr/bin/python3 -c "import json; print(json.load(open('/var/lib/desk-update/state.json')).get('version', 0))" 2>/dev/null || echo 0)
  echo
  tail -n 4 /opt/desk/logs/update.log 2>/dev/null | cut -c1-160 || true
  echo
  if [ "$v" -ge 1 ] 2>/dev/null; then
    echo "LISTO: el desk ya está en la versión v$v (sigue en PAPER)."
    echo "Las próximas actualizaciones se instalan solas. Ya puedes cerrar esta ventana."
  else
    echo "Actualizador instalado, pero la primera actualización aún no se ha aplicado."
    echo "Se reintenta sola cada 10 minutos. El desk sigue funcionando en PAPER."
  fi
}

main "$@"
