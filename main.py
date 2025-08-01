import argparse
from urllib.parse import parse_qsl
from modules import injection, session


def setup_parsers():
    """Sets up and returns the argument parser."""

    # --- Main Parser Setup ---
    parser = argparse.ArgumentParser(
        description="Nata-Probe: A modular toolkit for web vulnerability analysis.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Create subparsers to handle different modules (e.g., 'inject', 'session').
    subparsers = parser.add_subparsers(dest="module", required=True, help="The module to run.")

    # --- Injection Module Parser ---
    parser_inject = subparsers.add_parser("inject", help="Run various injection attacks.")
    inject_subparsers = parser_inject.add_subparsers(dest="attack_type", required=True)

    # Command Injection Sub-parser
    parser_cmd = inject_subparsers.add_parser("cmd", help="Command injection.")
    parser_cmd.add_argument("url", help="Target URL.")
    parser_cmd.add_argument("-u", "--auth", required=True, help="'user:password'")
    parser_cmd.add_argument("--param", required=True, help="Vulnerable parameter.")
    parser_cmd.add_argument("--payload", required=True, help="Injection payload.")
    parser_cmd.add_argument("--method", default="POST", choices=['GET', 'POST'])

    # Boolean-Based SQLi Sub-parser
    parser_sqli_bool = inject_subparsers.add_parser("sqli-bool", help="Boolean-based blind SQLi.")
    parser_sqli_bool.add_argument("url", help="Target URL.")
    parser_sqli_bool.add_argument("-u", "--auth", required=True, help="'user:password'")
    parser_sqli_bool.add_argument("--data", required=True, help="POST data string.")
    parser_sqli_bool.add_argument("--param-to-fuzz", required=True, help="Parameter to inject.")
    parser_sqli_bool.add_argument("--success-string", required=True, help="True condition string.")
    parser_sqli_bool.add_argument("--max-len", type=int, default=32)

    # Time-Based SQLi Sub-parser
    parser_sqli_time = inject_subparsers.add_parser("sqli-time", help="Time-based blind SQLi.")
    parser_sqli_time.add_argument("url", help="Target URL.")
    parser_sqli_time.add_argument("-u", "--auth", required=True, help="'user:password'")
    parser_sqli_time.add_argument("--data", required=True, help="POST data string.")
    parser_sqli_time.add_argument("--param-to-fuzz", required=True, help="Parameter to inject.")
    parser_sqli_time.add_argument("--sleep-time", type=int, default=3)
    parser_sqli_time.add_argument("--max-len", type=int, default=32)

    # --- Session Module Parser ---
    parser_session = subparsers.add_parser("session", help="Session brute-forcing.")
    parser_session.add_argument("url", help="Target URL.")
    parser_session.add_argument("-u", "--auth", required=True, help="'user:password'")
    parser_session.add_argument("--range", required=True, help="'start:stop:step'")
    parser_session.add_argument("--template", required=True, help="Cookie template.")
    parser_session.add_argument("--success-string", required=True, help="Valid session string.")
    parser_session.add_argument("--hex-encode", action="store_true", help="Hex-encode the ID.")

    return parser


def main():
    """Main function to parse arguments and run the appropriate module."""
    parser = setup_parsers()
    args = parser.parse_args()

    # --- Argument Parsing and Setup ---
    # Parse user:password from the --auth argument.
    try:
        user, password = args.auth.split(':', 1)
        auth = (user, password)
    except ValueError:
        print("[-] Error: Authentication must be in 'user:password' format.")
        return

    print(f"\n[*] Starting Nata-Probe against: {args.url}")
    print(f"[*] Module: {args.module}, Attack: {getattr(args, 'attack_type', 'brute-force')}\n")

    # --- Module Routing ---
    # Route to the 'injection' module based on the parsed command.
    if args.module == "inject":
        if args.attack_type == "cmd":
            injection.probe_with_baseline(
                args.url, auth, args.param, args.payload, method=args.method
            )
        else:
            # For SQLi, parse the POST data string into a dictionary.
            try:
                data_dict = dict(parse_qsl(args.data))
            except Exception as e:
                print(f"[-] Error parsing --data string: {e}")
                return

            # Route to the specific SQLi function.
            if args.attack_type == "sqli-bool":
                injection.probe_blind_sql_boolean_generic(
                    args.url, auth, data_dict, args.param_to_fuzz, args.success_string, args.max_len
                )
            elif args.attack_type == "sqli-time":
                injection.probe_blind_sql_time_generic(
                    args.url, auth, data_dict, args.param_to_fuzz, args.sleep_time, args.max_len
                )

    # Route to the 'session' module.
    elif args.module == "session":
        session.brute_force_session(
            args.url, auth, args.range, args.template, args.success_string, args.hex_encode
        )


if __name__ == "__main__":
    main()
