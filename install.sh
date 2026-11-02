#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
umask 077
REPO="astricmy/warp-screenshare-scanner"
TAG="v0.1.0"
VERSION="0.1.0"
printf '%s\n' 'WARP SCREENSHARE — instalação transparente' \
  'Vou instalar python, curl, android-tools, termux-api, aapt e apksigner pelo pkg.' \
  'apksigner usa Java. Execute bash install.sh --leve para omitir os dois verificadores de APK.' \
  'baixar um release fixo, conferir SHA-256 e criar o comando warp-scan.' \
  'O instalador não inicia coleta nem solicita root ou armazenamento.'
if [[ "$REPO" == "SEU_USUARIO/SEU_REPO" ]]; then
  printf '%s\n' 'Publicação pendente: a staff deve configurar o repositório e publicar o release.' >&2
  exit 1
fi
if [[ -z "${PREFIX:-}" || "$PREFIX" != /data/data/com.termux/files/usr ]]; then
  printf '%s\n' 'Execute este instalador no Termux oficial.' >&2
  exit 1
fi
if [[ "${1:-}" == "--leve" ]]; then
  pkg install -y python curl android-tools termux-api
else
  pkg install -y python curl android-tools termux-api aapt apksigner
fi
mkdir -p "$PREFIX/tmp"
TEMP_WARP="$(mktemp -d "$PREFIX/tmp/warp-install.XXXXXXXX")"
trap 'rm -rf -- "$TEMP_WARP"' EXIT
BASE_URL="https://github.com/$REPO/releases/download/$TAG"
ASSET="warp-screenshare-scanner-$VERSION.zip"
curl --proto '=https' --tlsv1.2 -fSL --max-time 120 "$BASE_URL/$ASSET" -o "$TEMP_WARP/$ASSET"
curl --proto '=https' --tlsv1.2 -fSL --max-time 60 "$BASE_URL/SHA256SUMS" -o "$TEMP_WARP/SHA256SUMS"
curl --proto '=https' --tlsv1.2 -fSL --max-time 60 "$BASE_URL/checksums.txt" -o "$TEMP_WARP/checksums.txt"
# O verificador é este código inspecionável, não um executável recebido do ZIP.
python - "$TEMP_WARP" "$ASSET" "$PREFIX" "$VERSION" <<'PY'
import hashlib, os, pathlib, re, shutil, stat, sys, zipfile
temp,asset,prefix,version=sys.argv[1:]
temp=pathlib.Path(temp); prefix=pathlib.Path(prefix)
archive=temp/asset
expected=(temp/'SHA256SUMS').read_text().strip().split()
if len(expected)!=2 or expected[1]!=asset or not re.fullmatch('[a-f0-9]{64}',expected[0]):
    raise SystemExit('SHA256SUMS inválido')
if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected[0]:
    raise SystemExit('ZIP divergente; nada instalado')
manifest={}
for line in (temp/'checksums.txt').read_text().splitlines():
    match=re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9_./-]+)',line)
    if not match: raise SystemExit('Manifesto inválido')
    digest,name=match.groups(); path=pathlib.PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or name in manifest: raise SystemExit('Caminho inseguro')
    manifest[name]=digest
if not {'scan.py','config.py','signatures.json','settings.json'} <= manifest.keys():
    raise SystemExit('Release incompleto')
stage=temp/'verified'; stage.mkdir()
with zipfile.ZipFile(archive) as zf:
    infos=zf.infolist()
    names=[i.filename for i in infos]
    if len(names)!=len(set(names)) or set(names)!=set(manifest)|{'checksums.txt'}:
        raise SystemExit('Conteúdo do ZIP difere do manifesto')
    if sum(i.file_size for i in infos)>10*1024*1024: raise SystemExit('Release excedeu limite')
    for info in infos:
        if stat.S_ISLNK(info.external_attr>>16): raise SystemExit('Link simbólico recusado')
        content=zf.read(info)
        if info.filename=='checksums.txt':
            if content!=(temp/'checksums.txt').read_bytes(): raise SystemExit('Manifestos divergentes')
        elif hashlib.sha256(content).hexdigest()!=manifest[info.filename]:
            raise SystemExit('Arquivo divergente')
        target=stage/info.filename; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(content)
base=prefix/'opt'/'warp-screenshare-scanner'
base.mkdir(parents=True,exist_ok=True)
target=base/version
if base.is_symlink() or target.is_symlink(): raise SystemExit('Destino simbólico recusado')
if target.exists():
    # Atualização idempotente da mesma tag; não apaga arquivos externos ao produto.
    for name,digest in manifest.items():
        path=target/name
        if path.is_symlink() or any(p.is_symlink() for p in path.parents): raise SystemExit('Link no destino')
        path.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(stage/name,path)
    shutil.copyfile(stage/'checksums.txt',target/'checksums.txt')
else:
    shutil.copytree(stage,target)
launcher=prefix/'bin'/'warp-scan'
if launcher.is_symlink(): raise SystemExit('Launcher simbólico recusado')
launcher.write_text('#!'+str(prefix/'bin/bash')+'\nexec '+str(prefix/'bin/python')+' '+str(target/'scan.py')+' "$@"\n')
launcher.chmod(0o700)
print('Instalado. Execute warp-scan; use warp-scan --test para demonstração.')
PY
printf '%s\n' 'Instale também o aplicativo Termux:API da mesma fonte do Termux.' \
  'Armazenamento: execute termux-setup-storage manualmente, se desejar autorizar.'
