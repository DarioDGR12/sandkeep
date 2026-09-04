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
│   ├── snapshot/          # DirStore: snap + mem + rootfs sucio por session_id
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

**2. Una microVM nueva por request, salvo `session_id`.**
Sin `session_id` cada job arranca limpio y se destruye con `defer`. Con `session_id` y `snapshot_dir`, después de Execute se pausa la VM, se escribe un snapshot Full (mem + snap + rootfs sucio) y el siguiente `/execute` de esa sesión hace `PUT /snapshot/load` en un proceso fresco. Si el restore falla o la topología de red no coincide (NIC vs deny-all), se borra el snap y se hace cold boot.

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
| `session_id` | Opcional; `[A-Za-z0-9_-]{1,128}`. Con backend firecracker + `snapshot_dir`, reusa la VM vía snapshot |

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
| `WARDEN_JAILER` | unset | Path al binario jailer (vacío = Firecracker directo) |
| `WARDEN_JAILER_SUDO` | unset | `1` para invocar el jailer con `sudo -n` |
| `WARDEN_JAILER_UID` / `_GID` | usuario actual | Credenciales después del exec |
| `WARDEN_NET_SUDO` | unset | `1` para `sudo -n` en `ip`/`nft` (también se activa si `WARDEN_JAILER_SUDO=1`) |
| `WARDEN_SNAPSHOT_DIR` | `data/snapshots` | Store de sesión; vacío = no reusar VM |

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
        Firecracker: restore snapshot si session_id tiene meta
          o jailer (opt) → spawn VMM → cgroup al PID
        → TAP+netns+veth+nft solo si allowlist no vacía
        → API configure → InstanceStart → wait guest-agent
  → Instance.Execute (JSON por vsock; el guest exec python/node)
  → snapshot best-effort (pause + PUT /snapshot/create) si hay session_id
  → defer Instance.Destroy (SendCtrlAltDel, SIGKILL, borrar workdir; el store de sesión se queda)
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

- **Sin TAP si allowlist vacía.** El guest no tiene L3. Si hay destinos: netns `warden-<id>`, TAP dentro del ns (`172.25.x.x/30`), veth uplink (`172.27.x.x/30`), NAT masquerade y nft **fail-closed en el veth del host** (forward policy drop; solo IPs resueltas de la allowlist). El jailer recibe `--netns`; sin jailer, Firecracker arranca con `ip netns exec`. El guest recibe IP por `ip=` en la cmdline del kernel.
- **Jailer opcional.** `WARDEN_JAILER=assets/jailer` (y casi siempre `WARDEN_JAILER_SUDO=1`): chroot en `{work_dir}/firecracker/<id>/root`, drop a uid/gid no-root, `/dev/kvm` + `/dev/net/tun` dentro del jail. El VMM ve `/vmlinux`, `/rootfs.ext4`, `/api.sock`.
- **seccomp del VMM ≠ seccomp del guest.** El jailer/Firecracker traen el filtro del VMM. `configs/seccomp.json` no se inyecta al proceso KVM.
- **cgroups.** Sin jailer: attach best-effort al PID. Con jailer: `--cgroup-version 2` si `WARDEN_JAILER_CGROUP=1`.
- **Copia del rootfs:** `cp --reflink=auto` y fallback a copy. El kernel se hardlinkea (es read-only). El store de sesión vive en `data/snapshots/` (nunca dentro del workdir de la VM: Destroy borra ese árbol).
- **Snapshots.** `PATCH /vm` pause → `PUT /snapshot/create` (Full). Restore: proceso fresco, solo logger, `PUT /snapshot/load` + `resume_vm`. El TAP se recrea con los **mismos** nombres/IPs (el `host_dev_name` va en el snap).
- **KVM anidado.** En este Cloud Agent `KVM_CREATE_VCPU` hace oops. En un `.metal`: `WARDEN_ITEST=1 go test ./internal/runtime -run TestFirecrackerRealVM`.

Jailer:

```bash
WARDEN_RUNTIME=firecracker \
WARDEN_JAILER=assets/jailer \
WARDEN_JAILER_SUDO=1 \
go run ./cmd/warden
```

## Lo que esto NO es (aún)

- Authn (API key, mTLS) — no exponer esto a Internet
- Rate limit ni cola de VMs
- Diff snapshots / pool de rootfs prewarmed
- Auditoría durable (el JSONL se pierde en cada deploy)

## Licencia

Apache License 2.0. Ver `LICENSE`.
