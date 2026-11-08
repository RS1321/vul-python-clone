"""Entry point for paired, factorial and repeated-study statistics."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from review.analyze_study import main

if __name__ == "__main__":
    main()
