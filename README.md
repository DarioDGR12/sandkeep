# Warden

Sandbox de ejecución de código para agentes de IA (Cursor, Devin, agentes propios), construido sobre **Firecracker microVMs**.

Este repositorio se llama `sandkeep`. El binario y el producto se llaman **Warden**: es la capa de seguridad entre el agente y el host real.

> Fase 1 (esta sesión): esqueleto compilable, API REST, pipeline de aislamiento con **stubs claros**, auditoría y tests. **No ejecuta código de agente en el host.** El backend `stub` solo simula el ciclo de vida de una microVM. Firecracker se cablea en la siguiente fase.

## Por qué existe

Un agente que puede escribir y correr código sin aislamiento puede:

- borrar o leer datos del host
- abrir conexiones de red no autorizadas (exfiltración)
- agotar CPU, RAM o disco (DoS al nodo)

Warden pone **cuatro barreras** (defensa en profundidad), no una sola:

| Capa | Qué corta | Dónde vive |
| --- | --- | --- |
| Firecracker microVM | Kernel y filesystem distintos al host | `internal/runtime` |
| cgroups | CPU, RAM, PIDs, disco | `internal/resources` |
| seccomp | Syscalls peligrosas (fail-closed) | `internal/resources` + `configs/seccomp.json` |
| Egress filter | Cualquier dial que no esté en allowlist | `internal/network` |

cgroups y seccomp se aplican al **proceso jailer de Firecracker en el host**, no "dentro" del guest. El filtro de egress se aplica en el TAP/iptables del host. El guest no es un socio de confianza.

## Estructura

El módulo Go está en la **raíz del repo** (no en una carpeta `warden/`). Así `cmd/warden` es el binario y no hay un módulo anidado. Es el layout idiomático de Go.

```
.
├── cmd/warden/            # main: env, señales, listen 0.0.0.0:$PORT
├── internal/
│   ├── api/               # HTTP: POST /execute, GET /health
│   ├── runtime/           # interfaz Runtime + stub + placeholder Firecracker
│   ├── resources/         # perfiles cgroups + seccomp
│   ├── network/           # egress fail-closed
│   ├── snapshot/          # save/restore (fase 2, no implementado)
│   └── audit/             # JSONL + logger en memoria para tests
├── configs/               # cgroups.json, seccomp.json, egress.json
├── go.mod
└── README.md
```

`internal/` no se puede importar desde otro módulo. El compilador de Go lo impide. Para un producto de seguridad eso es una frontera real, no una convención.

## Decisiones de arquitectura (fase 1)

**1. Interfaces, no Firecracker en el handler.**
`POST /execute` habla con `runtime.Runtime`, `resources.Limiter`, `network.Filter` y `audit.Logger`. El día que `WARDEN_RUNTIME=firecracker` funcione de verdad, el handler no cambia. Esto es inversión de dependencias y es lo que permite tests sin `/dev/kvm`.

**2. Una microVM nueva por request.**
Reusar VMs es una optimización (fase 2 + `internal/snapshot`). En fase 1 cada job arranca limpio y se destruye con `defer`. No hay estado residual ni vecinos ruidosos.

**3. El stub no evalúa código.**
Si el stub corriera `python -c ...` en el proceso de Warden, el MVP sería el agujero que el producto promete tapar. La respuesta lleva el banner `[warden-stub]` a propósito.

**4. Fail-closed en red y seccomp.**
`configs/egress.json` tiene allowlist vacía y `default_policy: deny`. El loader **rechaza** `default_policy: allow`. El perfil seccomp exige `SCMP_ACT_ERRNO` o kill, nunca allow-by-default.

**5. Solo stdlib.**
`net/http`, `encoding/json`, `log/slog`, `context`. Cero dependencias externas mientras aprendemos el dominio. Un router o un cliente de Firecracker se añaden cuando hagan falta.

**6. HTTP 200 = el sandbox terminó.**
Exit code ≠ 0 y timeout de guest son resultados válidos para un agente (`exit_code`, `timed_out`). 4xx/5xx significa que **Warden** rechazó o no pudo arrancar el job.

**7. Auditoría sin payload infinito.**
Cada evento guarda `code_sha256`, tamaño, preview de 256 bytes, `session_id`, `vm_id`, timestamps y resultado. El disco local es efímero en PaaS (Render, etc.); el JSONL es un buffer, no la fuente de verdad a largo plazo.

**8. Bind `0.0.0.0:$PORT`.**
Plataformas cloud inyectan `PORT`. Escuchar solo en `127.0.0.1` hace el servicio inalcanzable detrás del proxy.

## API

### `GET /health`

```json
{"status":"ok","backend":"stub"}
```

### `POST /execute`

```json
{
  "code": "print('hello')",
  "runtime": "python",
  "timeout": 30,
  "session_id": "abc"
}
```

| Campo | Reglas |
| --- | --- |
| `code` | Obligatorio, máx. 64 KiB |
| `runtime` | `python` o `node` (`python3` se normaliza a `python`) |
| `timeout` | 1–300 segundos; default 30 |
| `session_id` | Opcional; `[A-Za-z0-9_-]{1,128}` — se registra, **no** se reusa VM aún |

Respuesta 200:

```json
{
  "stdout": "[warden-stub] ...",
  "stderr": "",
  "exit_code": 0,
  "vm_id": "stub-1",
  "runtime": "python",
  "request_id": "...",
  "session_id": "abc",
  "duration_ms": 1,
  "timed_out": false,
  "backend": "stub"
}
```

El body HTTP está limitado a 1 MiB. Campos JSON desconocidos se rechazan.

## Cómo correrlo

Requiere Go 1.22+.

```bash
go test ./...
go run ./cmd/warden
```

Variables de entorno:

| Variable | Default | Qué hace |
| --- | --- | --- |
| `PORT` / `WARDEN_ADDR` | `8080` / `0.0.0.0:8080` | Listen |
| `WARDEN_RUNTIME` | `stub` | `stub` o `firecracker` (este último falla cerrado) |
| `WARDEN_CONFIG_DIR` | `configs` | Perfiles |
| `WARDEN_AUDIT_LOG` | `audit.jsonl` | Log JSONL |

```bash
curl -s localhost:8080/health
curl -s -X POST localhost:8080/execute \
  -H 'Content-Type: application/json' \
  -d '{"code":"print(1+1)","runtime":"python","timeout":10,"session_id":"demo"}'
```

## Pipeline de un request

```
POST /execute
  → validar JSON y contrato
  → Limiter.Apply (cgroups + seccomp; hoy noop documentado)
  → Runtime.Boot (microVM nueva)
  → Instance.Execute (código en el guest)
  → defer Instance.Destroy (siempre)
  → Audit.Record (éxito o error)
  → JSON al agente
```

`session_id` ya viaja por el pipeline. `internal/snapshot` es el hueco de fase 2 para `Save` / `Restore` en vez de boot en frío.

## Lo que esto NO es (aún)

- No hay Firecracker real ni rootfs/kernel empaquetados
- No hay authn (API key, mTLS) — no exponer esto a Internet
- No hay rate limit ni cola de VMs
- No hay snapshots de sesión
- El filtro de egress se consulta, no se programa en iptables
- El limiter no llama a `cgroup.controllers` todavía

## Licencia

Apache License 2.0. Ver `LICENSE`.
