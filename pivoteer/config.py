import sys
import os

iSight_public_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
iSight_private_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
vt_token = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
opendns_token = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX"

try: # try importing local_config from the working directory
    sys.path.insert(0, os.getcwd())
    import local_config
    iSight_public_key = local_config.iSight_public_key
    iSight_private_key = local_config.iSight_private_key
    vt_token = local_config.vt_token
    opendns_token = local_config.opendns_token
except ImportError:
    print 'No API keys defined!'
    print 'Create a local_config.py or set manually (e.g., pivoteer.config.vt_token = "YOURKEY")'
