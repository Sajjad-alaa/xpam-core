#!/usr/bin/env python
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'apps'))
from ops.celery._beat import main

if __name__ == '__main__':
    main()
