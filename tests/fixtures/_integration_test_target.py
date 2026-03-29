# Integration test fixture — deliberately vulnerable, never executed.
import subprocess
import os


def process_request(request_data: dict) -> dict:
    template = request_data.get("template", "default")
    # CWE-78: unsanitised user input passed directly to shell=True
    output = subprocess.check_output(
        f"render_template.sh {template}", shell=True
    )
    return {"result": output.decode()}


def get_report(query: str) -> str:
    # CWE-78: second injection point via os.popen
    return os.popen(f"generate_report {query}").read()
