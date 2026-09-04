# Warden

Sandbox de ejecución de código para agentes de IA (Cursor, Devin, agentes propios), construido sobre **Firecracker microVMs**.

Este repositorio se llama `sandkeep`. El binario y el producto se llaman **Warden**: es la capa de seguridad entre el agente y el host real.

> Fase 2: el backend `firecracker` ya habla con el VMM real (API Unix socket, vsock, guest-agent). El default sigue siendo `stub` para no exigir `/dev/kvm`. Con assets en `assets/` y `WARDEN_RUNTIME=firecracker`, `/execute` corre el código **dentro** de la microVM.

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
├── cmd/warden/            # control plane HTTP
├── cmd/guest-agent/       # PID 1 dentro de la microVM (vsock :52)
├── internal/
│   ├── api/               # POST /execute, GET /health
│   ├── runtime/           # Stub + Firecracker (API socket, vsock, lifecycle)
│   ├── guestproto/        # contrato JSON host↔guest
│   ├── resources/         # cgroups v2 + perfiles seccomp
│   ├── network/           # egress fail-closed
│   ├── snapshot/          # save/restore (aún no)
│   └── audit/             # JSONL
├── configs/               # cgroups, seccomp, egress, firecracker.json
├── scripts/               # fetch-assets, build-rootfs, setup-kvm
├── assets/                # kernel, rootfs, firecracker (no se commitean)
└── go.mod
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

**5. Cliente Firecracker propio, stdlib en el host.**
El host habla HTTP sobre un Unix socket (como documenta Firecracker) y vsock con el handshake `CONNECT <port>\n` / `OK …`. La única dependencia extra es `golang.org/x/sys` para que el **guest-agent** haga `AF_VSOCK` dentro de la VM.

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
| `WARDEN_RUNTIME` | `stub` | `stub` o `firecracker` |
| `WARDEN_CONFIG_DIR` | `configs` | Perfiles + `firecracker.json` |
| `WARDEN_AUDIT_LOG` | `audit.jsonl` | Log JSONL |
| `WARDEN_FC_BINARY` / `_KERNEL` / `_ROOTFS` | `assets/…` | Override de paths |
| `WARDEN_CGROUP_REQUIRED` | unset | Si es `1`, Boot falla cuando no se puede crear el cgroup |

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
  → Limiter.Apply (validación de perfil)
  → Runtime.Boot
        Firecracker: spawn VMM → cgroup al PID → API configure
        → sin NIC si allowlist vacía → InstanceStart
        → wait vsock + guest-agent
  → Instance.Execute (JSON por vsock; el guest exec python/node)
  → defer Instance.Destroy (SendCtrlAltDel, SIGKILL, borrar workdir)
  → Audit.Record
  → JSON al agente
```

El timeout de `POST /execute` cubre **solo el job**. El boot de la VM tiene su propio presupuesto (20s).

### Levantar Firecracker de verdad

```bash
./scripts/setup-kvm.sh
./scripts/fetch-assets.sh
./scripts/build-rootfs.sh          # sudo: apk en chroot + mkfs.ext4
WARDEN_RUNTIME=firecracker go run ./cmd/warden
```

Decisiones de fase 2 que importan:

- **Sin TAP.** Allowlist vacía ⇒ no se crea interfaz de red. El guest no tiene L3. Eso *es* el filtro de egress. Si la allowlist tiene entradas, Boot **falla** (no mentimos con una VM “con red”).
- **seccomp del VMM ≠ seccomp del guest.** Firecracker ya trae un filtro estricto para el proceso VMM (KVM ioctls). No le aplicamos `configs/seccomp.json`; ese perfil es para el jailer (siguiente paso).
- **cgroups al PID de Firecracker**, no a un nombre compartido `pending-vm`. En contenedores sin cgroup delegado el attach es best-effort (`WARDEN_CGROUP_REQUIRED=1` para fail-closed).
- **guest-agent es PID 1** (`init=/usr/local/bin/guest-agent`). Monta proc/sys/dev y escucha vsock :52.
- **Una copia del rootfs por VM** para no compartir escrituras. Pesado; snapshots/reflink vienen después.
- **KVM anidado.** Firecracker necesita crear vCPUs. En algunos hosts virtualizados (este Cloud Agent incluido) `KVM_CREATE_VCPU` provoca un oops del kernel; el runtime detecta que el VMM murió y lo reporta. En un `.metal` o una máquina con KVM no anidado, `WARDEN_ITEST=1 go test ./internal/runtime -run TestFirecrackerRealVM` es el smoke test.

## Lo que esto NO es (aún)

- Jailer (chroot + uid drop + seccomp custom del VMM)
- TAP + iptables para una allowlist no vacía
- Authn (API key, mTLS) — no exponer esto a Internet
- Rate limit ni cola de VMs
- Snapshots de sesión (`internal/snapshot`)
- Auditoría durable (el JSONL se pierde en cada deploy)

## Licencia

Apache License 2.0. Ver `LICENSE`.
