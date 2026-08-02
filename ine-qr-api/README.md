# INE QR Decoder — HTTP API

REST API que expone el decodificador de credenciales INE como servicio.
Acepta una foto de la credencial y devuelve los 18 campos biográficos más la foto extraída del QR.

---

## Inicio rápido

```bash
# 1. Configurar API key (opcional pero recomendado)
export API_KEY=tu_clave_secreta

# 2. Build + run desde la raíz del repo (un único Dockerfile)
docker build -t ine-qr-api .
docker run -d --name ine-qr-api \
  -p 8080:8080 \
  -e API_KEY="$API_KEY" \
  --read-only --tmpfs /tmp \
  ine-qr-api

# 3. Verificar que está vivo
curl http://localhost:8080/healthz
# {"status":"ok"}

# 4. Decodificar una credencial
curl -X POST http://localhost:8080/decode \
  -H "X-API-Key: $API_KEY" \
  -F "photo=@credencial.heic"
```

---

## Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `PORT` | `8080` | Puerto HTTP |
| `API_KEY` | _(ninguna)_ | Clave de acceso. Si no se define, no hay autenticación |
| `WORKERS` | `NumCPU × 5/4` | Decodificaciones simultáneas (cap del semáforo) |
| `QUEUE_WAIT_MS` | `2000` | Espera máxima para conseguir un slot antes de devolver 503 |
| `MAX_BODY_MB` | `25` | Tamaño máximo del body de la petición |
| `RATE_PER_SEC` | `5` | Tokens/segundo del rate limiter por API key (o IP). **`0` desactiva el rate limiter** |
| `RATE_BURST` | `10` | Burst del rate limiter (ignorado cuando `RATE_PER_SEC=0`) |
| `MAX_LONG_EDGE` | `3000` | Reescala lado largo de la imagen antes del scan QR. `0` = off |
| `READ_TIMEOUT_S` | `30` | `http.Server.ReadTimeout` |
| `WRITE_TIMEOUT_S` | `60` | `http.Server.WriteTimeout` |
| `IDLE_TIMEOUT_S` | `120` | `http.Server.IdleTimeout` |
| `HEADER_TIMEOUT_S` | `5` | `http.Server.ReadHeaderTimeout` (slowloris) |

---

## Endpoints

### `GET /healthz`

Comprueba que el servidor está activo.

**Respuesta:**
```json
{"status": "ok"}
```

---

### `POST /decode`

Decodifica una foto de credencial INE y devuelve los datos biográficos.

**Autenticación:** Header `X-API-Key: <valor>` (requerido si `API_KEY` está configurado).

Acepta **dos formatos de entrada** alternativos:

---

#### Formato 1 — File upload (multipart/form-data)

Envía la imagen como archivo.

```
POST /decode
Content-Type: multipart/form-data
X-API-Key: <clave>

Campo: photo  (archivo HEIC / JPG / PNG)
```

**curl:**
```bash
curl -X POST http://localhost:8080/decode \
  -H "X-API-Key: $API_KEY" \
  -F "photo=@credencial.heic"
```

**Python (requests):**
```python
import requests

with open("credencial.heic", "rb") as f:
    r = requests.post(
        "http://localhost:8080/decode",
        headers={"X-API-Key": "tu_clave"},
        files={"photo": ("credencial.heic", f, "image/heic")},
    )
print(r.json())
```

---

#### Formato 2 — Base64 JSON (application/json)

Envía la imagen codificada en base64 dentro de un objeto JSON.
Útil cuando el cliente no puede enviar multipart (p.ej. desde un frontend JS o un Lambda).

```
POST /decode
Content-Type: application/json
X-API-Key: <clave>

{
  "photo_base64": "<imagen en base64 estándar o URL-safe>",
  "filename": "credencial.heic"   ← opcional, determina el formato (HEIC/JPG/PNG)
}
```

**curl:**
```bash
B64=$(base64 -i credencial.heic)

curl -X POST http://localhost:8080/decode \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"photo_base64\": \"$B64\", \"filename\": \"credencial.heic\"}"
```

**Python:**
```python
import requests, base64

with open("credencial.heic", "rb") as f:
    b64 = base64.b64encode(f.read()).decode()

r = requests.post(
    "http://localhost:8080/decode",
    headers={"X-API-Key": "tu_clave", "Content-Type": "application/json"},
    json={"photo_base64": b64, "filename": "credencial.heic"},
)
print(r.json())
```

**JavaScript (fetch):**
```js
const file = document.querySelector('input[type=file]').files[0];
const b64  = btoa(String.fromCharCode(...new Uint8Array(await file.arrayBuffer())));

const res = await fetch("http://localhost:8080/decode", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": "tu_clave",
  },
  body: JSON.stringify({ photo_base64: b64, filename: file.name }),
});
console.log(await res.json());
```

---

#### Respuesta exitosa `200 OK`

```json
{
  "tipo":              "N",
  "cic":               "123456789",
  "ocr":               "1234567890123",
  "curp":              "ABCD900101HDFXXX00",
  "nombre":            "JUAN",
  "apellido1":         "GARCIA",
  "apellido2":         "LOPEZ",
  "entidad":           "09",
  "municipio":         "010",
  "seccion":           "1234",
  "etnia":             "",
  "vigencia":          "2013/2023",
  "sexo":              "H",
  "indiceHuella1":     "1",
  "indiceHuella2":     "",
  "version":           "C",
  "fechaGeneracion":   "20130415",
  "firmaVerificadora": "a1b2c3d4...",
  "foto_base64":       "UklGRg..."
}
```

`foto_base64` es la foto de la credencial extraída del QR, codificada en base64 estándar.
Decodifícala para obtener un archivo WebP de 96×129 px:

```python
import base64
with open("foto.webp", "wb") as f:
    f.write(base64.b64decode(data["foto_base64"]))
```

---

#### Respuestas de error

| Código | Causa |
|--------|-------|
| `400` | Body inválido, campo `photo` / `photo_base64` faltante, base64 inválido |
| `401` | `X-API-Key` incorrecto o ausente |
| `405` | Método distinto de POST |
| `413` | Body mayor a `MAX_BODY_MB` |
| `422` | El decodificador no pudo procesar la imagen (QR no visible, imagen borrosa) |
| `429` | Rate limit excedido para la API key/IP |
| `503` | Cola de workers saturada (todos los slots ocupados durante `QUEUE_WAIT_MS`) |

```json
{"error": "decode failed — check image quality and QR code visibility"}
```

---

## Concurrencia y rendimiento

El decodificador C corre **in-process** vía cgo (sin `fork+exec` por petición ni archivos temporales). El servidor combina cuatro mecanismos de control:

1. **Semáforo** de tamaño `WORKERS` que limita decodificaciones simultáneas.
2. **Cola con tope**: si los workers están ocupados, una petición espera hasta `QUEUE_WAIT_MS`; si vence el plazo se devuelve `503` con `Retry-After`.
3. **Rate limiter** por `X-API-Key` (o IP si no hay key): `RATE_PER_SEC` tokens/s con burst `RATE_BURST`. Excederlo devuelve `429`. **Apagable** con `RATE_PER_SEC=0` — útil cuando hay un API gateway delante (Kong, AWS API Gateway, Cloudflare) que ya hace rate limiting, o en despliegues internos con clientes de confianza.
4. **Timeouts del `http.Server`**: `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `MaxHeaderBytes` y `MaxBytesReader` cubren slowloris y bodies maliciosos.

Throughput observado en Apple M-series con `WORKERS=8` y `MAX_LONG_EDGE=3000`:

| Concurrencia | Throughput | p50 | p95 |
|--------------|-----------|-----|-----|
| Secuencial   | ~10 req/s | 96 ms | 100 ms |
| 4 paralelos  | ~37 req/s | 92 ms | 98 ms  |
| 8 paralelos  | ~66 req/s | 92 ms | 98 ms  |

Para escalar más allá de un servidor: **load balancer → múltiples contenedores** (el servicio es 100% stateless). El endpoint `/stats` expone contadores y latencias para alimentar a un colector externo.

---

## Despliegue

### Docker (recomendado)

El `Dockerfile` vive en la raíz del repo. Compila la librería estática pura en C (`libine_decode.a`) y la enlaza en la API Go vía cgo, todo en una sola imagen. No usa ni empaqueta `libPersonalCode.so` (la ruta del emulador no interviene en el servicio):

```bash
export API_KEY=una_clave_larga_y_segura

docker build -t ine-qr-api .
docker run -d \
  --name ine-qr-api \
  -p 8080:8080 \
  -e API_KEY="$API_KEY" \
  --read-only --tmpfs /tmp \
  --restart unless-stopped \
  ine-qr-api
```

`--read-only --tmpfs /tmp` reproduce el modo seguro que antes ofrecía `docker-compose.yml`: el rootfs queda inmutable y solo `/tmp` (donde la API escribe los archivos por petición) es escribible.

### Sin Docker (macOS / Linux)

```bash
# Requisitos: ine_decode compilado en ine-qr-c/
cd ine-qr-api
go build -o ine_api .

DECODER_PATH=../ine-qr-c/ine_decode \
API_KEY=tu_clave \
./ine_api
```

---

## Notas de seguridad

- **Nunca** loguees el contenido de las respuestas (contienen CURP, nombre, etc.).
- Usa **HTTPS** en producción (nginx reverse proxy con TLS o un API Gateway).
- El campo `filename` en el JSON body se usa **solo** para detectar la extensión; el contenido nunca se escribe bajo ese nombre.
- Las imágenes y directorios temporales se eliminan inmediatamente después de cada solicitud.
