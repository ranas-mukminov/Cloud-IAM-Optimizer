import sys
import os

# Add src to path to allow imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from audit_aws import main

if __name__ == "__main__":
    main()
