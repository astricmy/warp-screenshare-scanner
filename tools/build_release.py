"""Gera manifesto e ZIP reproduzível sem incluir dados locais ou segredos."""
from pathlib import Path
import hashlib
import json
import sys
import zipfile

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
import config


def source_files():
    top=["scan.py","config.py","settings.json","signatures.json","install.sh","README.md","SECURITY.md","CHANGELOG.md",".gitignore",".gitattributes"]
    files=[BASE/name for name in top]
    for directory in ("warp_scanner","worker","tests","tools","docs",".github"):
        for path in (BASE/directory).rglob("*"):
            if path.is_file() and not set(path.relative_to(BASE).parts)&{"__pycache__","node_modules",".wrangler","dist"} and path.suffix not in {".pyc",".log"} and not path.name.startswith((".env",".dev.vars")):
                files.append(path)
    return sorted(files,key=lambda p:p.relative_to(BASE).as_posix())


def main():
    files=source_files()
    manifest="".join(hashlib.sha256(p.read_bytes()).hexdigest()+"  "+p.relative_to(BASE).as_posix()+"\n" for p in files)
    (BASE/"checksums.txt").write_text(manifest,encoding="utf-8",newline="\n")
    output=BASE/"dist"
    output.mkdir(exist_ok=True)
    archive=output/f"warp-screenshare-scanner-{config.VERSION}.zip"
    with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as zf:
        for path in files+[BASE/"checksums.txt"]:
            info=zipfile.ZipInfo(path.relative_to(BASE).as_posix(),date_time=(2026,1,1,0,0,0))
            info.external_attr=0o100644<<16
            info.compress_type=zipfile.ZIP_DEFLATED
            zf.writestr(info,path.read_bytes())
    (output/"checksums.txt").write_text(manifest,encoding="utf-8",newline="\n")
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (output/"SHA256SUMS").write_text(f"{digest}  {archive.name}\n",encoding="ascii",newline="\n")
    print(json.dumps({"archive":archive.name,"files":len(files),"sha256":digest}))


if __name__=="__main__":
    main()
