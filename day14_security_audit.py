import os
import subprocess
from pathlib import Path


# --------------------------------------------------
# 1. PROJECT CONFIGURATION
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent
TASKS_DIR = PROJECT_DIR.parent

LOCAL_APP_DATA = os.getenv("LOCALAPPDATA")

if LOCAL_APP_DATA:
    GITLEAKS_PATH = (
        Path(LOCAL_APP_DATA)
        / "Microsoft"
        / "WinGet"
        / "Packages"
        / "Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe"
        / "gitleaks.exe"
    )
else:
    GITLEAKS_PATH = None


# --------------------------------------------------
# 2. DAY 1 TO DAY 13 FOLDERS
# --------------------------------------------------

DAY_FOLDERS = [
    "Day 1",
    "Day 2",
    "Day 3",
    "Day 4",
    "Day 5",
    "Day 6",
    "Day 7",
    "Day 8",
    "Day 9",
    "Day 10",
    "Day 11 activitywatch",
    "Day 12 Focus Tracker",
    "Day 13 Focus Metrics Sync",
]


# --------------------------------------------------
# 3. VERIFY ENVIRONMENT CONFIGURATION
# --------------------------------------------------

def verify_environment():
    print("\n--- Environment Configuration Check ---")

    env_file = PROJECT_DIR / ".env.example"

    if env_file.is_file():
        print("[OK] Example environment file exists.")
    else:
        print("[WARNING] .env.example was not found.")

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()

    if api_key and api_key != "your_openrouter_api_key_here":
        print("[OK] OpenRouter API key is configured.")
        print("[INFO] API key validity has not been verified.")
    else:
        print("[INFO] OpenRouter API key is not configured.")

    credentials_path = os.getenv(
        "FIREBASE_CREDENTIALS_PATH", ""
    ).strip()

    if credentials_path:
        path = Path(credentials_path)

        if not path.is_absolute():
            path = PROJECT_DIR / path

        if path.is_file():
            print("[OK] Firebase credentials file exists.")
        else:
            print("[WARNING] Firebase credentials file was not found.")
    else:
        print("[INFO] Firebase credentials path is not configured.")

    return env_file.is_file()


# --------------------------------------------------
# 4. SCAN A PROJECT FOLDER WITH GITLEAKS
# --------------------------------------------------

def scan_project(folder_name):
    folder_path = TASKS_DIR / folder_name

    print("\n" + "=" * 60)
    print(f"Scanning: {folder_name}")
    print("=" * 60)

    if not folder_path.is_dir():
        print("[WARNING] Folder not found. Skipping.")
        return "SKIPPED"

    if GITLEAKS_PATH is None or not GITLEAKS_PATH.is_file():
        print("[ERROR] Gitleaks executable was not found.")
        return "ERROR"

    try:
        result = subprocess.run(
            [
                str(GITLEAKS_PATH),
                "dir",
                str(folder_path),
                "--redact",
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )

        output = result.stdout + result.stderr

        if output.strip():
            print(output.strip())

        if result.returncode == 0:
            print(f"[PASS] {folder_name}: No leaks detected.")
            return "PASS"

        if result.returncode == 1:
            print(
                f"[FINDING] {folder_name}: "
                "Potential secrets detected."
            )
            return "FINDINGS"

        print(
            f"[ERROR] Gitleaks exited with code "
            f"{result.returncode}."
        )
        return "ERROR"

    except subprocess.TimeoutExpired:
        print(f"[ERROR] Scan timed out for {folder_name}.")
        return "ERROR"

    except OSError as error:
        print(
            f"[ERROR] Unable to scan folder: "
            f"{type(error).__name__}."
        )
        return "ERROR"


# --------------------------------------------------
# 5. DISPLAY SECURITY AUDIT SUMMARY
# --------------------------------------------------

def display_summary(summary):
    print("\n" + "=" * 60)
    print("DAY 1 TO DAY 13 SECURITY AUDIT SUMMARY")
    print("=" * 60)

    print(f"Projects listed: {len(DAY_FOLDERS)}")
    print(f"Scans without detected leaks: {len(summary['PASS'])}")
    print(f"Potential findings: {len(summary['FINDINGS'])}")
    print(f"Skipped folders: {len(summary['SKIPPED'])}")
    print(f"Scan errors: {len(summary['ERROR'])}")

    for category, folders in summary.items():
        if folders:
            print(f"\n{category}:")

            for folder in folders:
                print(f"  - {folder}")

    print("\nSecurity audit completed.")
    print("Review potential findings before deciding whether they are real secrets.")
    print("Note: Directory scans do not check complete Git history.")


# --------------------------------------------------
# 6. MAIN FUNCTION
# --------------------------------------------------

def main():
    print("=" * 60)
    print("AUTOMATED SECURITY AUDIT: DAY 1 TO DAY 13")
    print("=" * 60)

    print(f"Tasks directory: {TASKS_DIR}")

    verify_environment()

    if GITLEAKS_PATH is None or not GITLEAKS_PATH.is_file():
        print("\n[ERROR] Gitleaks executable was not found.")
        print("Please check your Gitleaks installation.")
        return

    summary = {
        "PASS": [],
        "FINDINGS": [],
        "SKIPPED": [],
        "ERROR": [],
    }

    for folder_name in DAY_FOLDERS:
        result = scan_project(folder_name)
        summary[result].append(folder_name)

    display_summary(summary)


# --------------------------------------------------
# 7. PROGRAM ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()