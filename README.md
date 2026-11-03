# Desk-updates

Canal de actualizaciones del desk privado de Álvaro.

- `latest.json`: número de versión, tamaño y huella sha256 del paquete, firmado con HMAC-SHA256.
- `releases/vN.bin`: el código de cada versión, cifrado con AES-256-GCM. Sin la clave no se puede leer.
- `vps_update.py`: el actualizador que corre en el servidor cada 10 minutos. Comprueba la firma, la huella y el cifrado; si algo no cuadra no instala nada, y si la versión nueva no arranca bien vuelve sola a la anterior.
- `bootstrap.sh`: instala el actualizador una sola vez.

Aquí no hay contraseñas, tokens ni datos. Las claves se derivan en el propio servidor y nunca se suben.
