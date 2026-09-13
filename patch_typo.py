import re

with open("analyzers/heuristics.py", "r") as f:
    src = f.read()

new_func = '''def _check_typosquat(parsed: dict) -> list:
    reg = parsed["registered_domain"].lower()
    if not reg or "." not in reg:
        return []

    name = reg.split(".")[0]

    # pecah jadi token: "paypa1-login" -> ["paypa1", "login"]
    tokens = [t for t in re.split(r"[-_.0-9]+", name) if t]
    if name not in tokens:
        tokens.append(name)

    out = []
    for tok in tokens:
        for pop in POPULAR_DOMAINS:
            pop_name = pop.split(".")[0]
            if tok == pop_name:
                if reg != pop:
                    out.append(_indicator(
                        "BRAND_IN_SUBDOMAIN",
                        f'Brand "{pop}" muncul di domain non-resmi',
                        50,
                        f'{reg} mengandung "{tok}"',
                    ))
                continue
            d = _levenshtein(tok, pop_name)
            max_d = 1 if len(pop_name) <= 5 else 2
            if 0 < d <= max_d:
                out.append(_indicator(
                    "TYPOSQUAT",
                    f'Mirip "{pop}"',
                    45,
                    f'{tok} vs {pop_name} (jarak {d})',
                ))
                break
        if out:
            break
    return out
'''

src = re.sub(
    r"def _check_typosquat\(parsed: dict\) -> list:.*?(?=\ndef _check_punycode)",
    new_func + "\n\n",
    src,
    flags=re.DOTALL,
)

if "import re" not in src:
    src = src.replace("import sys\nimport json", "import sys\nimport json\nimport re")

with open("analyzers/heuristics.py", "w") as f:
    f.write(src)

print("patched")
