import yaml
import sys
print(yaml.safe_load(open(sys.argv[1]))['image']['repository'])
