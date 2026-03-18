# Sovereign Validation Protocol (SOVP) — Python Core

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/Status-Patent_Pending-orange.svg)](https://litzki-systems.com/sovp)

## Overview

The **Sovereign Validation Protocol (SOVP)** is a deterministic infrastructure validation layer designed to establish cryptographic alignment and signal sovereignty in agentic architectures. This repository contains the reference implementation of the SOVP Core Engine in Python.

Developed by **Litzki Systems LLC**, SOVP operates under the **Zero Waste Architecture Protocol (ZWAP)** principles, ensuring zero external dependencies and maximum cryptographic efficiency for deep-tech environments.

### Patent Status
**U.S. Patent Application # 64/005,737**
*System and Method for Infrastructure Validation and Signal-to-Noise Separation via Sovereign Gateway.*

## Technical Foundation

- **Cryptography:** Ed25519 (RFC 8032) for immutable identity signatures.
- **Normalization:** RFC 8785 (JSON Canonicalization Scheme / JCS) to ensure deterministic hashing.
- **Integrity:** SHA-512 for high-entropy state validation.
- **Governance:** Full alignment with Sovereign Validation Protocol v1.0 (SOVP).

## Installation

```bash
# Clone the repository
git clone [https://github.com/litzki-systems/sovp-python.git](https://github.com/litzki-systems/sovp-python.git)
cd sovp-python

# Install dependencies
pip install cryptography canonicaljson
