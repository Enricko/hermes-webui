"""Synthetic Docker CLI for F02 controller boundary tests only.

This fixture never opens a socket, contacts an engine, or starts a container.
The test copies it into pytest's disposable temp directory and fills the
three literal placeholders before invoking it through --docker-bin.
"""

from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tarfile
import time


ROOT = Path(__MU_ROOT__)
SCENARIO = __MU_SCENARIO__
JQ_MARKER = Path(__MU_JQ_MARKER__)
STATE_PATH = ROOT / "fake-state.json"
LOG_PATH = ROOT / "fake-calls.jsonl"
ARCHIVE_PATH = ROOT / "candidate.tar"
ENGINE_ID = __MU_ENGINE_ID__
REPLACEMENT_ENGINE_ID = "mu-synthetic-replacement-engine-id"
UNIT_IMAGE_ID = "sha256:" + "1" * 64
CANDIDATE_IMAGE_ID = "sha256:" + "2" * 64
UNIT_CONTAINER_ID = "d" * 64
PREP_CONTAINER_ID = "e" * 64
FREEZE_CONTAINER_ID = "f" * 64
PREEXISTING_CONTAINER_ID = "c" * 64
PREEXISTING_IMAGE_ID = "sha256:" + "9" * 64
UNIT_LAYERS = ["sha256:" + "a" * 64]
IMAGE_ENV = ["PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"]
RUNTIME_CONFIG = {
    "User": "10001:10001",
    "WorkingDir": "/src",
    "Env": IMAGE_ENV,
    "Entrypoint": None,
    "Cmd": None,
    "Volumes": None,
    "OnBuild": None,
    "Healthcheck": None,
    "StopSignal": None,
    "Shell": None,
    "ExposedPorts": None,
}
TMPFS = {
    "/tmp": "rw,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=0700",
    "/run/mu-state": "rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700",
}


def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {"prep_removed": False, "unit_removed": False, "candidate_removed": False}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state), encoding="utf-8")


def evidence_dir() -> Path:
    return Path(os.environ["HOME"]).parent


def capture_lease_snapshot() -> None:
    lease = evidence_dir() / "lease.json"
    if lease.is_file():
        (ROOT / "lease-before-obstruction.bin").write_bytes(lease.read_bytes())


def obstruct_next_file() -> None:
    capture_lease_snapshot()
    (evidence_dir() / "lease.json.next").mkdir()


def arm_jq_failure() -> None:
    capture_lease_snapshot()
    JQ_MARKER.touch()


def record(argv: list[str]) -> None:
    with LOG_PATH.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "argv": argv,
                    "home": os.environ.get("HOME"),
                    "docker_config": os.environ.get("DOCKER_CONFIG"),
                    "tmpdir": os.environ.get("TMPDIR"),
                    "path": os.environ.get("PATH"),
                    "docker_host": os.environ.get("DOCKER_HOST"),
                    "docker_context": os.environ.get("DOCKER_CONTEXT"),
                    "http_proxy": os.environ.get("HTTP_PROXY"),
                    "aws_secret": os.environ.get("AWS_SECRET_ACCESS_KEY"),
                    "ssh_auth_sock": os.environ.get("SSH_AUTH_SOCK"),
                },
                sort_keys=True,
            )
            + "\n"
        )


def container_inspect(state: dict) -> dict:
    cid = UNIT_CONTAINER_ID
    nonce = state["nonce"]
    unit_id = state["controller_id"]
    worker_argv = state["worker_argv"]
    env = list(RUNTIME_CONFIG["Env"]) + [
        f"HERMES_MU_UNIT_ID={unit_id}",
        f"HERMES_MU_UNIT_NONCE={nonce}",
        "HERMES_MU_UNIT_SRC=/src",
        "HERMES_MU_UNIT_STATE=/run/mu-state",
    ]
    inspection = {
        "Id": cid,
        "Image": CANDIDATE_IMAGE_ID,
        "Config": {
            "User": "10001:10001",
            "WorkingDir": "/src",
            "Cmd": ["python3", "-I", "-S", "scripts/test_multiuser.py", *worker_argv],
            "Entrypoint": None,
            "Env": env,
            "Volumes": None,
            "Labels": {"hermes.f02.controller": unit_id},
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "NetworkMode": "none",
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": [],
            "SecurityOpt": ["no-new-privileges"],
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "CgroupnsMode": "private",
            "LogConfig": {"Type": "none", "Config": {}},
            "Binds": [],
            "Mounts": [],
            "Devices": [],
            "DeviceRequests": [],
            "VolumesFrom": [],
            "Links": [],
            "ExtraHosts": [],
            "Tmpfs": TMPFS,
            "PidsLimit": 256,
            "Memory": 2147483648,
            "MemorySwap": 2147483648,
            "NanoCpus": 2000000000,
            "RestartPolicy": {"Name": "no"},
            "AutoRemove": False,
            "Init": False,
        },
        "Mounts": [],
        "State": {
            "Status": (
                "exited" if state.get("settled") or state.get("killed")
                else "running" if state.get("started")
                else "created"
            ),
            "Running": bool(state.get("started") and not state.get("settled") and not state.get("killed")),
            "ExitCode": 137 if state.get("killed") else state.get("attach_rc", 0),
            "OOMKilled": False,
        },
    }
    config = inspection["Config"]
    host = inspection["HostConfig"]
    mutations = {
        "wrong-image": (inspection, "Image", "sha256:" + "9" * 64),
        "wrong-user": (config, "User", "0:0"),
        "wrong-workdir": (config, "WorkingDir", "/"),
        "wrong-command": (config, "Cmd", ["/bin/sh", "-c", "true"]),
        "entrypoint": (config, "Entrypoint", ["/bin/sh"]),
        "env": (config, "Env", config["Env"] + ["DOCKER_HOST=tcp://synthetic.invalid"]),
        "volumes": (config, "Volumes", {"/host": {}}),
        "writable-root": (host, "ReadonlyRootfs", False),
        "host-network": (host, "NetworkMode", "bridge"),
        "privileged": (host, "Privileged", True),
        "missing-cap-drop": (host, "CapDrop", []),
        "cap-add": (host, "CapAdd", ["SYS_ADMIN"]),
        "no-new-privileges": (host, "SecurityOpt", []),
        "host-pid": (host, "PidMode", "host"),
        "non-private-ipc": (host, "IpcMode", "host"),
        "host-uts": (host, "UTSMode", "host"),
        "host-userns": (host, "UsernsMode", "host"),
        "host-cgroupns": (host, "CgroupnsMode", "host"),
        "binds": (host, "Binds", ["/tmp:/host"]),
        "host-mounts": (host, "Mounts", [{"Type": "bind", "Source": "/tmp"}]),
        "top-mounts": (inspection, "Mounts", [{"Type": "bind", "Source": "/tmp"}]),
        "devices": (host, "Devices", [{"PathOnHost": "/dev/null"}]),
        "device-requests": (host, "DeviceRequests", [{"Capabilities": [["gpu"]]}]),
        "volumes-from": (host, "VolumesFrom", ["other-container"]),
        "links": (host, "Links", ["other-container:alias"]),
        "extra-hosts": (host, "ExtraHosts", ["synthetic.invalid:127.0.0.1"]),
        "tmpfs": (host, "Tmpfs", {"/tmp": "rw", "/run/mu-state": TMPFS["/run/mu-state"]}),
        "pids-limit": (host, "PidsLimit", 0),
        "memory": (host, "Memory", 0),
        "cpus": (host, "NanoCpus", 0),
        "restart": (host, "RestartPolicy", {"Name": "always"}),
        "auto-remove": (host, "AutoRemove", True),
        "init": (host, "Init", True),
        "log-driver": (host, "LogConfig", {"Type": "json-file", "Config": {}}),
    }
    if SCENARIO in mutations:
        target, key, value = mutations[SCENARIO]
        target[key] = value
    return inspection


def probe_inspect(state: dict, container_id: str) -> dict:
    inspection = {
        "Id": container_id,
        "Image": UNIT_IMAGE_ID,
        "Config": {
            "User": "10001:10001",
            "WorkingDir": "/src",
            "Cmd": ["/bin/true"],
            "Entrypoint": None,
            "Env": list(RUNTIME_CONFIG["Env"]),
            "Volumes": None,
            "Labels": {"hermes.f02.controller": state.get("controller_id")},
        },
        "HostConfig": {
            "NetworkMode": "none",
            "LogConfig": {"Type": "none", "Config": {}},
            "ReadonlyRootfs": True,
            "Binds": [],
            "Mounts": [],
            "Devices": [],
            "DeviceRequests": [],
            "VolumesFrom": [],
            "Tmpfs": {},
        },
        "Mounts": [],
        "State": {"Status": "created", "Running": False, "Pid": 0},
    }
    if SCENARIO == "probe-running":
        inspection["State"].update({"Status": "running", "Running": True, "Pid": 123})
    elif SCENARIO == "probe-pid":
        inspection["State"]["Pid"] = 123
    elif SCENARIO == "probe-command":
        inspection["Config"]["Cmd"] = ["/bin/sh", "-c", "true"]
    elif SCENARIO == "probe-network":
        inspection["HostConfig"]["NetworkMode"] = "bridge"
    elif SCENARIO == "probe-mount":
        inspection["Mounts"] = [{"Type": "bind", "Source": "/synthetic"}]
    elif SCENARIO == "probe-volume":
        inspection["Config"]["Volumes"] = {"/anonymous": {}}
    elif SCENARIO == "probe-device":
        inspection["HostConfig"]["Devices"] = [{"PathOnHost": "/dev/synthetic"}]
    elif SCENARIO == "probe-log-driver":
        inspection["HostConfig"]["LogConfig"] = {"Type": "json-file", "Config": {}}
    return inspection


def copy_source_with_venv_link(
    archive: bytes, *, extra_entry: bool, change_file: bool = False
) -> bytes:
    source = tarfile.open(fileobj=io.BytesIO(archive), mode="r:*")
    output = io.BytesIO()
    with source, tarfile.open(fileobj=output, mode="w") as target:
        for member in source.getmembers():
            renamed = copy.copy(member)
            renamed.name = "src/" + member.name
            if member.isfile():
                handle = source.extractfile(member)
                content = handle.read()
                if change_file and member.name == "requirements.txt":
                    content += b"# synthetic source drift\n"
                    renamed.size = len(content)
                target.addfile(renamed, io.BytesIO(content))
            else:
                target.addfile(renamed)
        venv = tarfile.TarInfo("src/.venv")
        venv.type = tarfile.SYMTYPE
        venv.linkname = "/opt/mu/.venv"
        target.addfile(venv)
        if extra_entry:
            marker = b"untracked synthetic source change"
            info = tarfile.TarInfo("src/extra-synthetic-entry.txt")
            info.size = len(marker)
            target.addfile(info, io.BytesIO(marker))
    return output.getvalue()


def freeze_archive(content: bytes = b"synthetic preprovisioned unit image\n") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as target:
        member = tarfile.TarInfo("freeze.txt")
        member.size = len(content)
        target.addfile(member, io.BytesIO(content))
    return output.getvalue()


def emit_json(value: object) -> None:
    print(json.dumps(value, separators=(",", ":")))


def emit_json_with_recorded_size(value: object, label: str) -> None:
    serialized = json.dumps(value, separators=(",", ":")) + "\n"
    (ROOT / f"{label}-json-bytes.txt").write_text(
        str(len(serialized.encode("utf-8"))), encoding="ascii"
    )
    sys.stdout.write(serialized)
    sys.stdout.flush()


def requests_json_format(args: list[str]) -> bool:
    return any(
        args[index : index + 2] == ["--format", "{{json .}}"]
        for index in range(len(args) - 1)
    )


def flood(stream, size: int) -> None:
    stream.buffer.write(b"x" * size)
    stream.buffer.flush()


def worker_payload(state: dict) -> dict:
    status = "NOT_RUN" if SCENARIO == "worker-not-run" else "PASS"
    exit_code = 3 if status == "NOT_RUN" else 0
    mode = None if status == "NOT_RUN" else "pytest"
    tier = None if status == "NOT_RUN" else "unit"
    if SCENARIO == "worker-mode-mismatch":
        mode = "script"
    if SCENARIO == "worker-tier-mismatch":
        tier = "native"
    return {
        "schema": "hermes-webui/multiuser-launcher/1",
        "status": status,
        "exit_code": exit_code,
        "tier": tier,
        "mode": mode,
        "agent": "none",
        "reasons": [] if status == "PASS" else [{"code": "unit_admission_required", "detail": "synthetic"}],
        "tests": {"total": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 0} if status == "PASS" else None,
        "checks": None,
        "unit": {
            "id": state["controller_id"],
            "nonce": state["nonce"],
            "evidence": "advisory-worker-context",
            "context": {"uid": 10001, "gid": 10001, "src_readonly": True, "net_interfaces": [], "dockerenv": True},
        },
        "claims": {
            "agent_source_pin": False,
            "native_clients": False,
            "browser_privacy": False,
            "os_containment": False,
            "external_provider": False,
        },
    }


def spawn_stall_child() -> int:
    signal_marker = ROOT / "caught-signal.marker"
    pid_path = ROOT / "stall-child.pid"
    shell = (
        "trap 'printf caught >> " + shlex.quote(str(signal_marker))
        + "' HUP INT TERM PIPE XFSZ; while :; do /bin/sleep 30; done"
    )
    child = subprocess.Popen(["/bin/sh", "-c", shell], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid_path.write_text(str(child.pid), encoding="ascii")
    return child.pid


def main(argv: list[str]) -> int:
    record(argv)
    if len(argv) < 2 or argv[0] != "--host" or not argv[1].startswith("unix://"):
        print("unexpected engine selection", file=sys.stderr)
        return 97
    args = argv[2:]
    state = load_state()
    if args[:1] == ["info"]:
        state["info_calls"] = state.get("info_calls", 0) + 1
        save_state(state)
        current_id = ENGINE_ID
        if SCENARIO == "engine-switch-before-prep-removal" and state.get("prep_created"):
            current_id = REPLACEMENT_ENGINE_ID
        if SCENARIO == "engine-switch-before-unit-start" and state.get("unit_created"):
            current_id = REPLACEMENT_ENGINE_ID
        if SCENARIO == "engine-switch-before-unit-removal" and state.get("settled"):
            current_id = REPLACEMENT_ENGINE_ID
        if SCENARIO == "client-call-timeout":
            (ROOT / "client-call-entered.marker").touch()
            spawn_stall_child()
            while True:
                time.sleep(1)
        if SCENARIO == "info-stdout-overflow":
            flood(sys.stdout, 1048577)
        elif SCENARIO == "info-stderr-overflow":
            emit_json({"ID": current_id, "ServerVersion": "synthetic", "OperatingSystem": "Linux"})
            flood(sys.stderr, 65537)
        elif SCENARIO == "info-large-json" and "{{.ID}}" not in args:
            emit_json_with_recorded_size(
                {
                    "ID": current_id,
                    "ServerVersion": "synthetic",
                    "OperatingSystem": "Linux",
                    "SyntheticPadding": "x" * 70000,
                },
                "info",
            )
        elif "{{.ID}}" in args:
            print(current_id)
        else:
            emit_json({"ID": current_id, "ServerVersion": "synthetic", "OperatingSystem": "Linux"})
        return 0

    if args[:1] == ["build"]:
        if SCENARIO == "build-fail":
            print("synthetic image build failure", file=sys.stderr)
            return 12
        if SCENARIO == "build-stdout-overflow":
            flood(sys.stdout, 8388609)
            return 0
        if SCENARIO == "build-stderr-overflow":
            flood(sys.stderr, 8388609)
            return 0
        state["unit_tag"] = args[args.index("--tag") + 1]
        save_state(state)
        iidfile_index = next(
            index for index, arg in enumerate(args) if arg == "--iidfile"
        )
        Path(args[iidfile_index + 1]).write_text(UNIT_IMAGE_ID + "\n", encoding="ascii")
        if SCENARIO.startswith("journal-after-build"):
            if SCENARIO.endswith("-jq"):
                arm_jq_failure()
            else:
                obstruct_next_file()
        return 0

    if args[:2] == ["image", "inspect"]:
        ref = args[-1]
        if SCENARIO == "control-stderr-overflow" and ref.startswith("hermes-f02-unit:"):
            flood(sys.stderr, 65537)
            return 1
        if SCENARIO == "control-stdout-overflow" and ref.startswith("hermes-f02-unit:"):
            flood(sys.stdout, 65537)
            return 1
        if SCENARIO in {"inspect-stdout-overflow", "inspect-stderr-overflow"} and ref == UNIT_IMAGE_ID:
            if SCENARIO == "inspect-stdout-overflow":
                flood(sys.stdout, 1048577)
            else:
                flood(sys.stderr, 65537)
            return 0
        if ref == UNIT_IMAGE_ID and SCENARIO == "runtime-image-absent":
            print(f"Error: No such image: {ref}", file=sys.stderr)
            return 1
        if ref.startswith("hermes-f02-cand:") and SCENARIO.startswith("journal-intent-candidate-tag"):
            if SCENARIO.endswith("-jq"):
                arm_jq_failure()
            else:
                obstruct_next_file()
            print(f"Error: No such image: {ref}", file=sys.stderr)
            return 1
        if ref.startswith("hermes-f02-unit:") and SCENARIO.startswith("journal-intent-unit-tag"):
            if SCENARIO.endswith("-jq"):
                arm_jq_failure()
            else:
                obstruct_next_file()
            print(f"Error: No such image: {ref}", file=sys.stderr)
            return 1
        if ref.startswith("hermes-f02-unit:") and SCENARIO == "control-stderr-overflow":
            flood(sys.stderr, 65537)
            return 1
        if ref.startswith("hermes-f02-cand:") and SCENARIO == "candidate-tag-conflict":
            existing = {
                "Id": PREEXISTING_IMAGE_ID,
                "RootFS": {"Layers": UNIT_LAYERS},
                "Config": RUNTIME_CONFIG,
            }
            if "{{.Id}}" in args:
                print(PREEXISTING_IMAGE_ID)
            else:
                emit_json(existing)
            return 0
        if state.get("candidate_removed"):
            print(f"Error: No such image: {ref}", file=sys.stderr)
            return 1
        if ref == UNIT_IMAGE_ID or ref == state.get("unit_tag"):
            image_id = UNIT_IMAGE_ID
            layers = UNIT_LAYERS
        elif ref.startswith("hermes-f02-cand:") and not state.get("candidate_created"):
            print(f"Error: No such image: {ref}", file=sys.stderr)
            return 1
        elif ref.startswith("hermes-f02-unit:") and ref != state.get("unit_tag"):
            print(f"Error: No such image: {ref}", file=sys.stderr)
            return 1
        else:
            image_id = CANDIDATE_IMAGE_ID
            layers = UNIT_LAYERS + ["sha256:" + "b" * 64]
        if "{{.Id}}" in args:
            print(
                "sha256:" + "9" * 64
                if SCENARIO == "runtime-image-id-mismatch" and ref == UNIT_IMAGE_ID
                else image_id
            )
        else:
            config = copy.deepcopy(RUNTIME_CONFIG)
            image_config_mutations = {
                "implicit-volume": ("Volumes", {"/anonymous": {}}),
                "implicit-onbuild": ("OnBuild", ["RUN echo synthetic"]),
                "implicit-entrypoint": ("Entrypoint", ["/bin/sh"]),
                "implicit-healthcheck": ("Healthcheck", {"Test": ["CMD", "true"]}),
                "wrong-runtime-user": ("User", "0:0"),
                "wrong-runtime-workdir": ("WorkingDir", "/"),
                "runtime-config-env-mismatch": (
                    "Env",
                    IMAGE_ENV + ["MU_SYNTHETIC_CONFIG_DRIFT=1"],
                ),
            }
            if SCENARIO in image_config_mutations:
                key, value = image_config_mutations[SCENARIO]
                config[key] = value
            emitted_id = (
                "sha256:" + "9" * 64
                if SCENARIO == "runtime-image-id-mismatch" and ref == UNIT_IMAGE_ID
                else image_id
            )
            image = {"Id": emitted_id, "RootFS": {"Layers": layers}, "Config": config}
            if SCENARIO == "inspect-large-json" and ref == UNIT_IMAGE_ID:
                image["SyntheticPadding"] = "x" * 70000
                emit_json_with_recorded_size(image, "inspect")
            else:
                emit_json(image)
        return 0

    if args[:1] == ["create"]:
        name = args[args.index("--name") + 1]
        controller_id = args[args.index("--label") + 1].split("=", 1)[1]
        if name.startswith("hermes-f02-freeze-"):
            state.update({"controller_id": controller_id, "freeze_removed": False})
            save_state(state)
            print(FREEZE_CONTAINER_ID)
        elif name.startswith("hermes-f02-prep-"):
            state.update({"controller_id": controller_id, "prep_removed": False, "prep_created": True})
            save_state(state)
            if SCENARIO == "create-malformed-id":
                print("not-a-container-id")
            elif SCENARIO == "create-lost-reply":
                return 12
            elif SCENARIO.startswith("journal-after-create"):
                if SCENARIO.endswith("-jq"):
                    arm_jq_failure()
                else:
                    obstruct_next_file()
                print(PREP_CONTAINER_ID)
            else:
                print(PREP_CONTAINER_ID)
        else:
            state.update({"controller_id": controller_id, "started": False, "unit_removed": False, "unit_created": True})
            state["nonce"] = next(
                args[index + 1].split("=", 1)[1]
                for index, value in enumerate(args[:-1])
                if value == "--env"
                and args[index + 1].startswith("HERMES_MU_UNIT_NONCE=")
            )
            command_start = args.index(CANDIDATE_IMAGE_ID) + 1
            state["worker_argv"] = args[command_start + 4 :]
            save_state(state)
            if SCENARIO == "capture-failed":
                (evidence_dir() / "worker.stdout").mkdir()
            print(UNIT_CONTAINER_ID)
        return 0

    if args[:1] == ["cp"]:
        if args[1:] in (
            [f"{FREEZE_CONTAINER_ID}:/opt/mu/freeze.txt", "-"],
            [f"{PREP_CONTAINER_ID}:/opt/mu/freeze.txt", "-"],
        ):
            if SCENARIO == "freeze-output-overflow":
                flood(sys.stdout, 1048577)
                return 0
            if SCENARIO == "wrong-freeze":
                sys.stdout.buffer.write(freeze_archive(b"synthetic mismatching freeze\n"))
            else:
                sys.stdout.buffer.write(freeze_archive())
            if SCENARIO == "socket-swap-before-prep-removal":
                socket_path = argv[1].removeprefix("unix://")
                os.unlink(socket_path)
                replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    replacement.bind(socket_path)
                finally:
                    replacement.close()
            return 0
        if args[1:] == ["-", f"{PREP_CONTAINER_ID}:/src"]:
            ARCHIVE_PATH.write_bytes(sys.stdin.buffer.read())
            save_state(state)
            return 0
        if args[1:] == [f"{UNIT_CONTAINER_ID}:/src", "-"]:
            archive = ARCHIVE_PATH.read_bytes()
            sys.stdout.buffer.write(
                copy_source_with_venv_link(
                    archive,
                    extra_entry=SCENARIO == "extra-source",
                    change_file=SCENARIO == "changed-source",
                )
            )
            return 0
        print("unexpected copy", file=sys.stderr)
        return 97

    if args[:1] == ["commit"]:
        state["candidate_created"] = True
        state["candidate_tag"] = args[-1]
        save_state(state)
        if SCENARIO == "commit-lost-reply":
            return 12
        if SCENARIO.startswith("journal-after-commit"):
            if SCENARIO.endswith("-jq"):
                arm_jq_failure()
            else:
                obstruct_next_file()
        print(CANDIDATE_IMAGE_ID)
        return 0

    if args[:2] == ["container", "inspect"]:
        ref = args[-1]
        if ref not in (UNIT_CONTAINER_ID, PREP_CONTAINER_ID, FREEZE_CONTAINER_ID):
            if ref.startswith("hermes-f02-prep-") and SCENARIO.startswith("journal-intent-prep"):
                if SCENARIO.endswith("-jq"):
                    arm_jq_failure()
                else:
                    obstruct_next_file()
                print(f"Error: No such container: {ref}", file=sys.stderr)
                return 1
            if SCENARIO == "container-name-conflict" and ref.startswith("hermes-f02-"):
                if "{{.Id}}" in args:
                    print(PREEXISTING_CONTAINER_ID)
                else:
                    emit_json({"Id": PREEXISTING_CONTAINER_ID, "Config": {"Labels": {}}})
                return 0
            if SCENARIO == "container-name-unknown" and ref.startswith("hermes-f02-"):
                print("synthetic engine state unavailable", file=sys.stderr)
                return 12
            print(f"Error: No such container: {ref}", file=sys.stderr)
            return 1
        if ref == PREP_CONTAINER_ID:
            removed = state.get("prep_removed")
        elif ref == FREEZE_CONTAINER_ID:
            removed = state.get("freeze_removed")
        else:
            removed = state.get("unit_removed")
        if removed:
            print(f"Error: No such container: {ref}", file=sys.stderr)
            return 1
        if requests_json_format(args):
            if ref in (PREP_CONTAINER_ID, FREEZE_CONTAINER_ID):
                if SCENARIO == "probe-inspect-stdout-overflow":
                    flood(sys.stdout, 1048577)
                    return 0
                emit_json(probe_inspect(state, ref))
            else:
                if SCENARIO == "unit-inspect-stdout-overflow":
                    flood(sys.stdout, 1048577)
                    return 0
                emit_json(container_inspect(state))
        elif "{{.State.Running}}" in args:
            print("true" if state.get("started") and not state.get("killed") else "false")
        else:
            print(UNIT_CONTAINER_ID if ref == UNIT_CONTAINER_ID else PREP_CONTAINER_ID)
        return 0

    if args[:3] == ["container", "start", "--attach"]:
        state.update({"started": True, "settled": False})
        save_state(state)
        (ROOT / "attach-entered.marker").touch()
        if SCENARIO in {"attach-timeout", "interrupt-attach", "client-call-timeout", "operation-deadline"}:
            spawn_stall_child()
            while True:
                time.sleep(1)
        if SCENARIO == "worker-stdout-overflow":
            flood(sys.stdout, 4194305)
            return 0
        if SCENARIO == "worker-stderr-overflow":
            flood(sys.stderr, 1048577)
            return 0
        if SCENARIO == "capture-failed":
            spawn_stall_child()
        payload = worker_payload(state)
        line = "MULTIUSER_RESULT " + json.dumps(payload, separators=(",", ":"))
        if SCENARIO == "duplicate-worker-result":
            print(line)
        print(line)
        attach_rc = 17 if SCENARIO == "worker-attach-mismatch" else payload["exit_code"]
        state["attach_rc"] = attach_rc
        state["settled"] = SCENARIO != "daemon-still-running"
        save_state(state)
        if SCENARIO == "worker-attach-mismatch":
            return 17
        return attach_rc

    if args[:2] == ["container", "kill"]:
        state["killed"] = True
        save_state(state)
        return 0

    if args[:3] == ["container", "rm", "-f"]:
        ref = args[-1]
        if ref == FREEZE_CONTAINER_ID:
            state["freeze_removed"] = True
        elif ref == PREP_CONTAINER_ID:
            state["prep_removed"] = True
        else:
            if SCENARIO != "unit-removal-unverified":
                state["unit_removed"] = True
        save_state(state)
        return 0

    if args[:2] == ["image", "rm"]:
        state["candidate_removed"] = True
        save_state(state)
        return 0

    print("unexpected synthetic Docker command: " + " ".join(args), file=sys.stderr)
    return 97


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
