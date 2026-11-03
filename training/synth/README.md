# Locally supplied Semgrep metadata

`gen_targeted.py` expects `semgrep_rules.json` in this directory. That file contains Semgrep registry rule content and is deliberately **not distributed** with this repository. It is listed in `.gitignore`.

If your own use is permitted by the Semgrep Rules License, create the file locally from metadata you are authorized to use, or adapt the generator to use your own rule catalog. Do not commit or redistribute the resulting registry-derived file or datasets embedding its rule text. The bundled tiny SARIF uses self-written demo messages instead.

The expected local JSON shape is an object keyed by a short rule name, with the fields consumed by `gen_targeted.py`: `check_id`, `severity`, `confidence`, `cwe`, and `message`.
