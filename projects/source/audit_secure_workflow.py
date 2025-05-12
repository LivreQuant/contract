# audit_secure_workflow.py
import argparse
import json
from services.audit_verification_service import AuditVerificationService


def main():
    parser = argparse.ArgumentParser(description="Secure Blockchain File Verification")
    parser.add_argument(
        "--csv", required=True, help="Path to blockchain transaction CSV"
    )
    parser.add_argument(
        "--config",
        help="Path to config JSON file (alternative to specifying files/params)",
    )
    parser.add_argument(
        "--public-key", required=True, help="Path to public key PEM file"
    )
    parser.add_argument("--output", help="Path to save audit report JSON")

    # File verification arguments (if not using config file)
    parser.add_argument("--book", help="Path to book file to verify")
    parser.add_argument("--research", help="Path to research file to verify")
    parser.add_argument("--params", help="Path to parameters JSON file")

    args = parser.parse_args()

    try:
        # Initialize the service
        service = AuditVerificationService(args.csv)

        # Load configuration
        if args.config:
            with open(args.config, "r") as f:
                config = json.load(f)
        else:
            # Create configuration from individual arguments
            config = {"files": [], "parameters": None}

            if args.book:
                config["files"].append({"path": args.book, "type": "book"})

            if args.research:
                config["files"].append({"path": args.research, "type": "research"})

            if args.params:
                with open(args.params, "r") as f:
                    config["parameters"] = json.load(f)

        # Generate secure audit report
        report = service.generate_secure_audit_report(
            files_to_verify=config.get("files", []),
            params_dict=config.get("parameters"),
            public_key_path=args.public_key,
        )

        # Print the report
        service.print_secure_audit_report(report)

        # Save report if requested
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            print(f"\nAudit report saved to {args.output}")

        # Return success/failure
        return 0 if report["all_verified"] else 1

    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
