# Module8 Vulnerability Scanner Pipeline

Run all team scanners from one entrypoint:

```bash
python app.py
```

Common settings are in `config.py`.

Team scanner folders live under `scanner/`:

- `scanner/bac_scanner/`
- `scanner/exposure_scanner/`
- `scanner/auth_session_scanner/`
- `scanner/webshell_scanner/`

Each scanner module should expose:

```python
def run_scan(config):
    ...
```
