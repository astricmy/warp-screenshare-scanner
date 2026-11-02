"""Varredura local sem exibir valores suspeitos. Não substitui revisão humana."""
from pathlib import Path
import re
import subprocess
import sys

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(Path(__file__).resolve().parent))
from build_release import source_files

PATTERNS=[re.compile(rb'https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api(?:/v\d+)?/webhooks/[0-9]{10,}/[A-Za-z0-9_.-]{20,}'),
          re.compile(rb'\b(?:ghp_|github_pat_|sk_live_|sk-proj-)[A-Za-z0-9_]{24,}'),
          re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')]


def suspicious(raw):
    return any(pattern.search(raw) for pattern in PATTERNS)


def main():
    failures=[]
    for path in source_files():
        if suspicious(path.read_bytes()):
            failures.append(path.relative_to(BASE).as_posix())
    # Analisa cada blob alcançável no histórico quando há repositório local.
    history=subprocess.run(["git","rev-list","--objects","--all"],cwd=BASE,capture_output=True)
    objects=history.stdout.decode(errors="replace").splitlines() if history.returncode==0 else []
    for row in objects:
        sha=row.split(" ",1)[0]
        kind=subprocess.run(["git","cat-file","-t",sha],cwd=BASE,capture_output=True)
        if kind.stdout.strip()!=b"blob":continue
        raw=subprocess.run(["git","cat-file","blob",sha],cwd=BASE,capture_output=True).stdout
        if suspicious(raw):failures.append("histórico:"+sha[:12])
    if failures:
        print("Possíveis segredos em: "+", ".join(failures))
        return 1
    print(f"Sem padrões de segredo detectados em {len(source_files())} arquivos e {len(objects)} objetos Git. Revisão manual continua necessária.")
    return 0


if __name__=="__main__":sys.exit(main())
