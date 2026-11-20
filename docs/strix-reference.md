# Strix reference notes

Reference checkout: [usestrix/strix at a1ccf777](https://github.com/usestrix/strix/tree/a1ccf777d80e812edf23fc8b82bdc17def6143ac). This was a targeted source review. A line-by-line audit was not completed.

| Reference | Observation |
| --- | --- |
| `pyproject.toml` | Python 3.12+, OpenAI Agents SDK, LiteLLM and Apache-2.0 license. |
| `strix/core/agents.py` and `strix/core/execution.py` | The coordinator tracks agent state separately from the execution loop. |
| `strix/runtime/backends.py` | The default backend is Docker, with a registry for alternate backends. |
| `strix/report/coverage.py` | The report distinguishes what agents claim from what the runtime observed and records incomplete runs. Shrike likewise exposes incomplete analysis separately from findings. |
| `strix/skills/__init__.py` | The project layers operator skill directories over packaged guidance. |
| `AGENTS.md` | Upstream documents local and managed workflows, including remediation and retesting. This does not establish which features are available on every commercial plan. |

Shrike is an independent local source reviewer. There is no performance or coverage comparison with Strix.
