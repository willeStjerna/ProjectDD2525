#!/usr/bin/env python3
"""
Main entry point to run the entire project workflow with a single command.
This script will:
1. Generate the full accuracy test suite.
2. Run the accuracy test runner to evaluate the detector.
"""

import subprocess
import sys
import os

def main():
    """Main function to execute the project workflow."""
    
    # --- Introduction ---
    print("=================================================")
    print("  Encoded Script Detection Project Workflow      ")
    print("=================================================")
    
    # Define the scripts to be run in order
    detector_script = "detector.py"
    test_suite_script = "accuracy_test_suite.py"
    test_runner_script = "accuracy_test_runner.py"
    
    # Check if necessary files exist before running
    required_files = [detector_script, test_suite_script, test_runner_script]
    for f in required_files:
        if not os.path.exists(f):
            print(f"\nError: Required script '{f}' not found.")
            print("Please ensure all scripts are in the same directory.")
            sys.exit(1)

    try:
        # --- Step 1: Generate the test files ---
        print(f"\n[STEP 1/2] Running '{test_suite_script}' to generate test files...")
        subprocess.run([sys.executable, test_suite_script], check=True)
        print(f"[SUCCESS] Test suite created successfully.")
        
        # --- Step 2: Run the evaluation ---
        print(f"\n[STEP 2/2] Running '{test_runner_script}' to evaluate the detector...")
        subprocess.run([sys.executable, test_runner_script, detector_script], check=True)
        print(f"[SUCCESS] Accuracy evaluation complete.")

    except subprocess.CalledProcessError as e:
        print(f"\nError: A step in the workflow failed.")
        print(f"Command '{' '.join(e.cmd)}' returned non-zero exit status {e.returncode}.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nWorkflow interrupted by user.")
        sys.exit(1)

    # --- Conclusion ---
    print("\n=================================================")
    print("  Project workflow finished successfully!        ")
    print("=================================================")
    print("You can now view the following generated reports:")
    print("  - `detection_report.txt` (Aggregated details of all detections)")
    print("  - `accuracy_test_results.json` (Detailed machine-readable results)")

if __name__ == "__main__":
    main()