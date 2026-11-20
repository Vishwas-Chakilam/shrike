# Shrike

Shrike reviews local Python source for explicit shell execution, unsafe YAML loaders, and disabled TLS verification. It parses source without executing it and needs no Docker, network, model keys, or runtime dependencies.

```powershell
python -m shrike.cli --target path/to/python/project --output .shrike
```

Run from this checkout or install it into an active virtual environment with `python -m pip install .` to use the `shrike` command. Open `.shrike/index.html` for the browser report. JSON, CSV, and SARIF exports are in the same folder.

| Exit code | Meaning |
| --- | --- |
| 0 | Review completed with no findings at or above `--fail-on`. |
| 1 | Execution failed or coverage was incomplete. Consult the report when available. |
| 2 | Findings met the threshold, which defaults to `high`, or the command line was invalid. |

These rules match explicit settings in Python syntax. They do not trace data flow or establish exploitability. Imports inside functions and reassigned import names can affect detection. Hidden and common dependency directories are skipped, and files over 1 MiB or files that cannot be parsed are reported as coverage issues.

Run the tests with `python -m unittest discover -s tests -v`. A GitHub Actions example is available under [examples](examples/github-actions.yml).

The [Strix reference notes](docs/strix-reference.md) describe which parts of the upstream checkout were inspected. Shrike's source is MIT licensed.
