# Contributing to sovp-python

This is the reference implementation of an open protocol. Contributions that improve correctness, interoperability, or test coverage are welcome.

## What to contribute

- **Bug fixes** — anything that causes `sovp.core` to deviate from the protocol draft
- **Test vectors** — fixed-input/output pairs for cross-implementation interoperability testing
- **Roadmap items** — features listed in the README Roadmap table
- **Documentation** — clarifications, typo fixes, example corrections

If you want to propose a change to the protocol itself (not just this implementation), the right venue is the IETF draft: [draft-litzki-sovp-05](https://litzki-systems.com/sovp).

## How to submit a change

1. Fork the repository and create a branch from `main`.
2. Make your changes. Keep commits focused — one logical change per commit.
3. Run the existing tests: `python -m pytest tests/`
4. Open a pull request against `main`. Describe what the change does and why.

There is no CLA. By submitting a pull request you agree that your contribution will be licensed under the project's [Apache 2.0 license](LICENSE).

## Code style

- Python 3.9+, no external dependencies beyond those in `pyproject.toml`
- Follow the existing module structure (`sovp/core.py`, `sovp/cli.py`)
- No docstrings for obvious functions; add a comment only when the reason is non-obvious

## Reporting issues

Open a GitHub issue. Include the Python version, OS, and a minimal reproducer.

## Contact

[info@litzki-systems.com](mailto:info@litzki-systems.com)
