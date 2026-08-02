#!/bin/sh
# Re-vendor the Semantic UI stylesheet, the Lucide icon masks and the Lato faces
# into web/assets/. The page must render with no request leaving this app's own
# origin, so everything it needs is embedded in the binary rather than linked.
set -e

CDN=https://cdn.semantic-ui.com
VERSION=canary
ROOT=$(dirname "$0")/..
ASSETS=$ROOT/web/assets

# only the icons the pages actually use — the full Lucide sheet is 46 KB of
# definitions for icons nothing here references
ICONS="moon sun copy check radio-tower triangle-alert list-checks circle-check
circle-x circle-alert flask-conical terminal book plug network shield-alert bug"

echo "stylesheet"
curl -fsS "$CDN/css@$VERSION" -o "$ASSETS/semantic.css"

echo "fonts"
for face in Regular Italic Semibold Bold; do
  curl -fsS "$CDN/fonts@$VERSION/lato/LatoLatin-$face.woff2" \
    -o "$ASSETS/LatoLatin-$face.woff2"
done

echo "icons"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
{
  echo "/* Lucide icons, vendored as data URIs. Regenerate with scripts/vendor-assets.sh */"
  echo ":root {"
  for icon in $ICONS; do
    curl -fsS "$CDN/icons@$VERSION/lucide/$icon.svg" -o "$work/$icon.svg"
    body=$(sed 's/<!--.*-->//' "$work/$icon.svg" | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//')
    enc=$(printf '%s' "$body" | sed 's/"/%22/g; s/#/%23/g; s/</%3C/g; s/>/%3E/g')
    printf '  --icon-%s: url("data:image/svg+xml,%s");\n' "$icon" "$enc"
  done
  echo "}"
} > "$ASSETS/icons.css"

echo "done — $(du -sh "$ASSETS" | cut -f1) in $ASSETS"
