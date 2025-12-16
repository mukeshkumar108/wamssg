#!/bin/bash
set -euo pipefail

CMD=("$@")
PROFILE_BASE="/app/.wwebjs_auth"

# Ensure permissions are correct for non-root runtime
chown -R whatsapp:nodejs /app/out /app/.wwebjs_auth /app/.wwebjs_cache 2>/dev/null || true

# If no Chromium is running, clear stale singleton locks in user data dirs
if ! pgrep -f "chromium|chrome|google-chrome" >/dev/null 2>&1; then
  echo "ℹ️ Checking for stale Chromium locks under $PROFILE_BASE"
  find "$PROFILE_BASE" -maxdepth 4 -type f \( -name "SingletonLock" -o -name "SingletonSocket" -o -name "SingletonCookie" \) -print -delete 2>/dev/null || true
else
  echo "ℹ️ Chromium process detected, skipping lock cleanup"
fi

# Drop privileges to whatsapp user for runtime
if [ "$(id -u)" = "0" ]; then
  if command -v runuser >/dev/null 2>&1; then
    exec runuser -u whatsapp -- "${CMD[@]}"
  else
    exec su -s /bin/sh whatsapp -c "exec ${CMD[*]}"
  fi
fi

exec "${CMD[@]}"
