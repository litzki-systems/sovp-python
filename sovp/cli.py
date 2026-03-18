import argparse
import json
import sys
from sovp.core import generate_keypair, sign_identity, verify_identity

def main():
    """Command Line Interface for the Sovereign Validation Protocol (SOVP)."""
    parser = argparse.ArgumentParser(description="SOVP Core CLI - Sovereign Validation Protocol")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.required = True

    # Command: generate-keypair
    subparsers.add_parser("generate-keypair", help="Generates a new Ed25519 keypair")

    # Command: sign
    parser_sign = subparsers.add_parser("sign", help="Signs an identity metadata payload")
    parser_sign.add_argument("--payload", required=True, help="Path to raw JSON payload file")
    parser_sign.add_argument("--privkey", required=True, help="Base64 encoded private key")

    # Command: verify
    parser_verify = subparsers.add_parser("verify", help="Verifies a signature against a payload (Psi_core resonance)")
    parser_verify.add_argument("--payload", required=True, help="Path to original JSON payload file")
    parser_verify.add_argument("--sig", required=True, help="Base64 encoded signature")
    parser_verify.add_argument("--pubkey", required=True, help="Base64 encoded public key")

    args = parser.parse_args()

    if args.command == "generate-keypair":
        priv, pub = generate_keypair()
        print("--- SOVP Ed25519 Keypair ---")
        print(f"Private Key (Base64) : {priv}")
        print(f"Public Key  (Base64) : {pub}")
        print("----------------------------")

    elif args.command == "sign":
        try:
            with open(args.payload, 'r') as f:
                metadata = json.load(f)
            signature = sign_identity(args.privkey, metadata)
            print(f"Generated Signature: {signature}")
        except Exception as e:
            print(f"Error processing payload: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "verify":
        try:
            with open(args.payload, 'r') as f:
                metadata = json.load(f)
            is_valid = verify_identity(metadata, args.sig, args.pubkey)
            if is_valid:
                print("Psi_core = 1: Verification SUCCESSFUL. Cryptographic alignment established.")
            else:
                print("Psi_core = 0: Verification FAILED. State drift or manipulation detected.", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Error processing validation: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()