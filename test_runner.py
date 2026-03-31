"""
test_runner.py
==============
Interactive test runner for the Route Cipher + Custom Hash system.
Takes all inputs manually from the user via the terminal.

To run:
    python test_runner.py

Make sure route_cipher_core.py is in the same folder.
"""

from route_cipher_core import sender_encrypt, receiver_decrypt, custom_hash

SEP  = "─" * 60
DSEP = "═" * 60


def print_header():
    print(DSEP)
    print("  Route Cipher + Custom Hash — Interactive Test Runner")
    print("  (Educational use only — not for production use)")
    print(DSEP)


def get_int(prompt: str, min_val: int = 2, max_val: int = 50) -> int:
    """Prompt until user enters a valid integer in [min_val, max_val]."""
    while True:
        try:
            val = int(input(prompt))
            if min_val <= val <= max_val:
                return val
            print(f"  Please enter a number between {min_val} and {max_val}.")
        except ValueError:
            print("  Invalid input. Please enter a whole number.")


def get_yes_no(prompt: str) -> bool:
    """Prompt until user enters y or n."""
    while True:
        choice = input(prompt).strip().lower()
        if choice in ("y", "yes"):
            return True
        if choice in ("n", "no"):
            return False
        print("  Please enter y or n.")


def run_test_case(label: str):
    """Run one complete test case with user-supplied inputs."""
    print(f"\n{SEP}")
    print(f"  TEST CASE: {label}")
    print(SEP)

    # ── Inputs ────────────────────────────────────────────────
    message = input("  Enter plaintext message : ").strip()
    if not message:
        print("  Empty message — skipping.")
        return

    cols = get_int("  Enter key (number of columns, 2–20) : ", min_val=2, max_val=20)

    tamper = get_yes_no("  Simulate tampering? (y/n) : ")

    # ── Sender side ───────────────────────────────────────────
    print(f"\n  {SEP}")
    print("  SENDER PIPELINE")
    print(f"  {SEP}")
    packet = sender_encrypt(message, cols)

    # ── Optional tampering ────────────────────────────────────
    if tamper:
        ct = list(packet["ciphertext"])
        original_first = ct[0]
        ct[0] = "Z" if ct[0] != "Z" else "A"
        packet["ciphertext"] = "".join(ct)
        print(f"\n  [!] TAMPER: First byte changed from '{original_first}' "
              f"to '{ct[0]}'")
        print(f"  [!] Modified ciphertext : {packet['ciphertext']}")

    # ── Receiver side ─────────────────────────────────────────
    print(f"\n  {SEP}")
    print("  RECEIVER PIPELINE")
    print(f"  {SEP}")
    receiver_decrypt(packet, cols)


def run_hash_only():
    """Let the user just hash a message and see the digest."""
    print(f"\n{SEP}")
    print("  HASH ONLY — compute custom_hash(message)")
    print(SEP)
    message = input("  Enter message to hash : ").strip()
    digest = custom_hash(message.upper().replace(" ", ""))
    print(f"  Hash digest : {digest}")


def show_menu() -> str:
    print(f"\n{DSEP}")
    print("  MENU")
    print("─" * 60)
    print("  1 — Run a test case (encrypt → optional tamper → decrypt)")
    print("  2 — Hash only (just compute H(M))")
    print("  3 — Exit")
    print(DSEP)
    return input("  Choose option (1/2/3) : ").strip()


# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print_header()
    case_number = 1

    while True:
        choice = show_menu()

        if choice == "1":
            run_test_case(label=f"Test Case {case_number}")
            case_number += 1
        elif choice == "2":
            run_hash_only()
        elif choice == "3":
            print(f"\n{DSEP}")
            print("  Exiting. Goodbye.")
            print(DSEP)
            break
        else:
            print("  Invalid choice. Please enter 1, 2, or 3.")
