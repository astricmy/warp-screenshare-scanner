"""Descobre raízes reais do Android para inventário de nomes, sem abrir arquivos pessoais."""
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path


SYSTEM = ("system", "system_ext", "product", "vendor", "vendor_dlkm", "odm", "odm_dlkm",
          "system_dlkm", "oem", "cache", "metadata", "cust", "preload")
_BLOCK_FS = {"ext4", "erofs", "f2fs", "squashfs", "vfat", "exfat", "ntfs", "ntfs3", "fuseblk"}
_VOLUME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_UUID = re.compile(r"[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}\Z")
_SKIP = {"/dev", "/proc", "/sys", "/mnt", "/storage", "/data_mirror", "/linkerconfig",
         "/debug_ramdisk", "/second_stage_resources", "/sdcard", "/config"}
_VIRTUAL_FS = {"tmpfs", "ramfs", "proc", "sysfs", "tracefs", "debugfs", "configfs",
               "cgroup", "cgroup2", "selinuxfs", "bpf", "devpts", "binder", "functionfs"}


@dataclass(frozen=True)
class Area:
    path: Path
    label: str
    kind: str
    prune: tuple = ()
    display_root: Path | None = None
    volume_label: str = ""

    @property
    def privileged(self):
        return self.kind != "termux"

    def canonical(self, path):
        value = Path(path).as_posix()
        if value.startswith("/data/media/"):
            value = "/storage/emulated/" + value[len("/data/media/"):]
        elif value.startswith("/data/data/"):
            value = "/data/user/0/" + value[len("/data/data/"):]
        elif value.startswith("/mnt/media_rw/"):
            value = "/storage/" + value[len("/mnt/media_rw/"):]
        return value

    def key(self, path):
        return self.canonical(path)

    def display_path(self, path):
        if self.kind in ("removable", "adopted"):
            return (self.volume_label or self.label) + "/" + Path(path).relative_to(self.display_root or self.path).as_posix()
        return Path(path).as_posix()


def _mounts(text):
    mounts = {}
    for line in text.splitlines():
        before, sep, after = line.partition(" - ")
        fields = before.split()
        system = after.split()
        if not sep or len(fields) < 6 or not system:
            continue
        path = fields[4]
        if not path.startswith("/") or "\\" in path or ".." in Path(path).parts:
            continue
        mounts[path] = (fields[2], fields[3], system[0])
    return mounts


def _directories(path):
    try:
        with os.scandir(path) as entries:
            return [item.name for item in entries if item.is_dir(follow_symlinks=False)]
    except OSError:
        return None


def discover(ctx):
    primary = Path(ctx.storage)
    areas = [Area(primary, "Armazenamento compartilhado principal", "primary")]
    # Uma raiz fornecida por um teste ou outro host jamais dispara buscas fora dela.
    if not re.fullmatch(r"/storage/emulated/[0-9]+", primary.as_posix()) or not Path("/system/bin/getprop").is_file():
        return areas, []
    notes = []
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as mount_file:
            text = mount_file.read(2 * 1024 * 1024 + 1)
        mounts = _mounts(text[:2 * 1024 * 1024])
        if len(text) > 2 * 1024 * 1024:
            notes.append("Tabela de montagens parcialmente lida.")
    except OSError:
        mounts = {}
        notes.append("Tabela de montagens indisponível.")
    capability = "root" if ctx.privilege.get("root") else "adb" if ctx.privilege.get("adb") else "none"
    if capability != "none":
        # ADB, su e o aplicativo podem ter visões distintas de /storage e /data.
        table = ctx.run(["cat", "/proc/self/mountinfo"], requires=capability, timeout=5, max_bytes=2 * 1024 * 1024)
        if table.ok:
            mounts.update(_mounts(table.text))
        else:
            notes.append("Montagens da sessão privilegiada não verificadas.")
    listing = ctx.run(["sm", "list-volumes", "all"], requires=capability, timeout=5, max_bytes=16384)
    public = set()
    adopted = set()
    for line in listing.text.splitlines() if listing.ok else ():
        fields = line.split()
        if len(fields) != 3 or fields[1] not in {"mounted", "mounted_ro"}:
            continue
        volume = fields[2]
        if volume == "null" or not _VOLUME.fullmatch(volume):
            continue
        if fields[0].startswith("public:"):
            public.add(volume)
        elif fields[0].startswith("private:") and _UUID.fullmatch(volume):
            adopted.add(volume)
    children = _directories("/storage")
    for mount in mounts:
        match = re.fullmatch(r"/storage/([^/]+)", mount)
        if match:
            public.add(match[1])
        match = re.fullmatch(r"/mnt/expand/([^/]+)", mount)
        if match and _UUID.fullmatch(match[1]):
            adopted.add(match[1])
    if children is None and not listing.ok:
        notes.append("A listagem de volumes externos ficou restrita às montagens visíveis.")
    public.update(children or [])
    public = sorted(name for name in public if _VOLUME.fullmatch(name) and name not in {"emulated", "self"})
    backing = {m.split("/")[-1] for m in mounts if re.fullmatch(r"/mnt/media_rw/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", m)}
    for n, name in enumerate(sorted(set(public) | backing), 1):
        label = f"Volume compartilhado {n}"
        if name in public:
            areas.append(Area(Path("/storage") / name, label, "removable"))
        if name in backing and (name not in (children or []) and "/storage/" + name not in mounts):
            areas.append(Area(Path("/mnt/media_rw") / name, label + " (montagem física)", "removable", volume_label=label))
    for n, name in enumerate(sorted(adopted), 1):
        areas.append(Area(Path("/mnt/expand") / name, f"Volume interno adotado {n}", "adopted"))
    profiles = {name for name in _directories("/storage/emulated") or () if re.fullmatch(r"[0-9]+", name)}
    env_path = os.environ.get("EXTERNAL_STORAGE", "")
    if re.fullmatch(r"/storage/emulated/[0-9]+", env_path):
        profiles.add(Path(env_path).name)
    for name in sorted(profiles - {primary.name}):
        areas.append(Area(primary.parent / name, f"Armazenamento do perfil {name}", "profile"))

    home = Path.home()
    if re.fullmatch(r"/data/(?:data|user/[0-9]+)/com\.termux/files/home", home.as_posix()):
        areas.append(Area(home.parent, "Arquivos privados do Termux", "termux"))
    areas.append(Area(Path("/data"), "Dados internos do Android", "data"))
    areas.append(Area(Path("/data/local/tmp"), "Arquivos temporários locais do Android", "data"))
    # Inclui partições específicas do fabricante efetivamente observadas, além
    # de diretórios do sistema em aparelhos com layout system-as-root.
    partitions = {"/" + name for name in SYSTEM if os.path.isdir("/" + name) and not os.path.islink("/" + name)}
    for path, (_, root, system) in mounts.items():
        if (re.fullmatch(r"/[a-zA-Z][a-zA-Z0-9_-]*", path) and system in _BLOCK_FS and root == "/"
                and path not in _SKIP | {"/data", "/apex"}):
            partitions.add(path)
    for path in sorted(partitions):
        areas.append(Area(Path(path), f"Partição {path}", "system"))

    if os.path.isdir("/apex") or "/apex" in mounts:
        # Um módulo APEX costuma aparecer em dois pontos de montagem (com e
        # sem versão). Caminhos de versões distintas continuam elegíveis.
        aliases = []
        for path, identity in mounts.items():
            module, at, _ = path.partition("@")
            if at and re.fullmatch(r"/apex/[a-zA-Z0-9._-]+", module) and mounts.get(module) == identity:
                aliases.append(Path(path))
        areas.append(Area(Path("/apex"), "Módulos ativos do Android", "system", tuple(sorted(aliases))))

    # find -xdev para na fronteira de cada montagem. Agenda montagens reais
    # aninhadas separadamente, inclusive as vistas FUSE de Android/data e obb.
    known = {a.path for a in areas}
    submount = 0
    for name, (_, _, system) in sorted(mounts.items()):
        path = Path(name)
        if path in known or system not in _BLOCK_FS | {"fuse", "sdcardfs", "fuseblk"}:
            continue
        parent = next((a for a in areas if a.path in path.parents), None)
        if parent is None or parent.path.as_posix() == "/apex":
            continue
        if not all(_VOLUME.fullmatch(part) for part in path.relative_to(parent.path).parts):
            notes.append("Uma montagem com caminho não reconhecido ficou fora do inventário.")
            continue
        submount += 1
        areas.append(Area(path, f"{parent.label} (submontagem {submount})", parent.kind,
                          display_root=parent.display_root or parent.path, volume_label=parent.volume_label or parent.label))
        known.add(path)

    # A raiz cobre arquivos diretamente em / e diretórios ordinários da
    # partição raiz. Os atalhos, volumes e sistemas virtuais ficam fora dela.
    areas.append(Area(Path("/"), "Raiz do Android", "system"))
    finalized = []
    for area in areas:
        excluded = set(area.prune)
        # As raízes sob /data com acesso por travessia também são buscadas se
        # o Android bloquear a listagem do diretório /data pelo próprio app.
        excluded.update(other.path for other in areas if area.path in other.path.parents)
        excluded.update(Path(name) for name, (_, _, fs) in mounts.items()
                        if area.path in Path(name).parents and fs in _VIRTUAL_FS)
        if area.path == Path("/"):
            excluded.update(Path(name) for name in _SKIP)
        # Elimina descendentes já cobertos por uma exclusão ancestral.
        prunes = tuple(sorted(path for path in excluded if not any(p in excluded for p in path.parents)))
        finalized.append(replace(area, prune=prunes))
    return finalized, notes
