"""Triagem offline por vizinho mais próximo (TF-IDF binário e similaridade de cosseno)."""
import math
import re
from collections import Counter
from functools import lru_cache


HIGH = "Priorizar revisão do código"
NORMAL = "Revisão normal"
UNKNOWN = "Amostra insuficiente para priorizar"

# Exemplos sintéticos rotulados. Os trechos são dados, nunca são executados.
EXAMPLES = {
    HIGH: (
        'local src = game:HttpGet("fixture"); loadstring(src)()',
        'loadstring(game:HttpGet("fixture"))()',
        'local f = loadstring(readfile("fixture")); f()',
        'local cfg = getgenv(); cfg.flag = true; hookfunction(target, callback)',
        'local old = hookmetamethod(game, "__namecall", newcclosure(callback))',
        'for _, obj in ipairs(getgc(true)) do if type(obj) == "function" then hookfunction(obj, cb) end end',
        'getgenv().enabled = true; queue_on_teleport(readfile("fixture"))',
        'local previous = getthreadidentity(); setthreadidentity(level); setthreadidentity(previous)',
        'local fn = getscriptclosure(script); local constants = getconstants(fn); setconstant(fn, index, value)',
        'local original = gethiddenproperty(object, name); sethiddenproperty(object, name, value)',
    ),
    NORMAL: (
        "Tutorial: loadstring e HttpGet são nomes de funções mencionadas neste exemplo.",
        "This guide explains why loadstring and getgenv are blocked. Never run unknown code.",
        "Documentação de API. Como reconhecer chamadas de hookfunction e hookmetamethod.",
        "WARNING: attempt to call a nil value. Stack Begin. Script stopped. Stack End.",
        "Relatório do scanner: padrões encontrados no arquivo de exemplo. Revisão manual.",
        'local players = game:GetService("Players"); print(players.LocalPlayer.Name)',
        'local part = Instance.new("Part"); part.Parent = workspace',
        'Manual: getthreadidentity() e setthreadidentity() são exemplos de nomes de funções.',
        'Warning: gethiddenproperty is unsupported, skipping property inspection.',
    ),
}
TOKEN = re.compile(r"""(?:"[^"\n]{0,250}"|'[^'\n]{0,250}'|[a-z_][\w]*|\d+|[().:=,;])""", re.I)


def _features(text):
    # O modelo só recebe uma amostra limitada, mesmo com --max-file-kb alto.
    parts = [text] if len(text) <= 12288 else [
        text[:4096], text[len(text)//2 - 2048:len(text)//2 + 2048], text[-4096:]
    ]
    features = set()
    for part in parts:
        tokens = []
        for token in TOKEN.findall(part.casefold()):
            if token[0] in ('"', "'"):
                token = '<str>'
            elif token.isdecimal():
                token = '<num>'
            tokens.append(token)
        features.update(tokens)
        features.update(a + " " + b for a, b in zip(tokens, tokens[1:]))
    return features


@lru_cache(maxsize=1)
def _model():
    documents = [(label, _features(text)) for label, texts in EXAMPLES.items() for text in texts]
    counts = Counter(term for _, terms in documents for term in terms)
    weights = {term: (1 + math.log((len(documents) + 1) / (count + 1))) ** 2
               for term, count in counts.items()}
    examples = [(label, terms, math.sqrt(sum(weights[t] for t in terms))) for label, terms in documents]
    return weights, examples


def review_priority(text):
    weights, examples = _model()
    sample = _features(text)
    known = sample.intersection(weights)
    if not known:
        return UNKNOWN
    # Termos fora do vocabulário reduzem a similaridade com o conjunto de referência.
    norm = math.sqrt(sum(weights[t] for t in known) + len(sample - known))
    scores = {HIGH: 0.0, NORMAL: 0.0}
    for label, terms, example_norm in examples:
        score = sum(weights[t] for t in known & terms) / (norm * example_norm)
        scores[label] = max(scores[label], score)
    best = max(scores, key=scores.get)
    if scores[best] < 0.25 or abs(scores[HIGH] - scores[NORMAL]) < 0.08:
        return UNKNOWN
    return best


_SIGNALS = (
    ({"getthreadidentity", "setthreadidentity"}, "Consulta e alteração da identidade da thread no mesmo trecho."),
    ({"getscriptclosure", "setconstant"}, "Acesso à função de um script e alteração de constante no mesmo trecho."),
    ({"gethiddenproperty", "sethiddenproperty"}, "Leitura e alteração de propriedade oculta no mesmo trecho."),
)
# Reconhece chamadas diretas. Métodos em objetos podem ser de bibliotecas comuns.
_CALL = re.compile(r"(?<![\w.:])([A-Za-z_]\w*)\s*\(")
_LITERAL = re.compile(r"""--|\[(=*)\[|["'`]""")


def _without_literals(sample):
    """Retira comentários e literais Lua antes de verificar a estrutura."""
    parts = []
    pos = 0
    while (match := _LITERAL.search(sample, pos)) is not None:
        parts.append(sample[pos:match.start()])
        opener = match[0]
        start = match.end()
        if opener == "--":
            long_open = re.match(r"\[(=*)\[", sample[start:])
            if long_open is None:
                end = sample.find("\n", start)
                pos = len(sample) if end < 0 else end
                parts.append(" ")
                continue
            close = "]" + long_open[1] + "]"
            start += long_open.end()
        elif opener.startswith("["):
            close = "]" + match[1] + "]"
        else:
            pos = start
            while pos < len(sample):
                ch = sample[pos]
                pos += 1
                if ch == "\\":
                    pos += 1
                elif ch == opener:
                    break
            parts.append(" ")
            continue
        end = sample.find(close, start)
        pos = len(sample) if end < 0 else end + len(close)
        parts.append(" ")
    parts.append(sample[pos:])
    return "".join(parts)


def review_candidate(text):
    """Busca um segundo sinal por similaridade e estrutura, com motivo fixo para revisão."""
    sample = text[:12288]
    if "```" in sample or not any(all(name in sample for name in required) for required, _ in _SIGNALS):
        return None
    code = _without_literals(sample).strip()
    if not re.match(r"(?:local\s+\w+|(?:if|do|return|for)\b|[A-Za-z_]\w*\s*[=(])", code):
        return None
    # Um exemplo que define esses nomes localmente pode ser uma implementação de teste.
    calls = set(_CALL.findall(re.sub(r"([.:])\s+", r"\1", code)))
    local_names = set(re.findall(r"\b(?:function|local)\s+([A-Za-z_]\w*)\s*[=(]", code))
    for required, explanation in _SIGNALS:
        if required <= calls and required.isdisjoint(local_names):
            if review_priority(code) == HIGH:
                return explanation
    return None
