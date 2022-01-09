#!/usr/bin/python3
import yaml
import sys
with open(sys.argv[1]) as f:
    chart = yaml.safe_load(f)
    print(chart['version'])
