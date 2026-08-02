#!/bin/sh
# every rung reads the chain off disk, so the secrets land there first
set -e
printf '%s' "$WT_CERT_PEM" > /cert.pem
printf '%s' "$WT_KEY_PEM" > /key.pem

# rung A: the validated-era library pin
/wt-legacy -cert /cert.pem -key /key.pem -bind fly-global-services -qlog /tmp/qlog-legacy &

# rung B: the independent stack
/wt-rust fly-global-services 4438 &

# the control owns the probe page and stays in the foreground as the main process
exec /wt-lab -wtcert le -cert /cert.pem -key /key.pem -bind fly-global-services -qlog /tmp/qlog
