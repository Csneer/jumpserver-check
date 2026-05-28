#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/root/jumpserver-check}"
SERVICE_NAME="${SERVICE_NAME:-jumpserver-cleanup-admin.service}"
UNIT_SOURCE="${UNIT_SOURCE:-${PROJECT_DIR}/deploy/systemd/${SERVICE_NAME}}"
UNIT_TARGET="/etc/systemd/system/${SERVICE_NAME}"

if [[ $EUID -ne 0 ]]; then
  echo "This installer must run as root because it writes ${UNIT_TARGET}." >&2
  exit 2
fi
if [[ ! -f "${UNIT_SOURCE}" ]]; then
  echo "Missing unit file: ${UNIT_SOURCE}" >&2
  exit 2
fi
if [[ ! -f "${PROJECT_DIR}/.env" ]]; then
  echo "Missing ${PROJECT_DIR}/.env; create it and set CLEANUP_ADMIN_TOKEN before enabling the service." >&2
  exit 2
fi
if ! grep -q '^CLEANUP_ADMIN_TOKEN=.\+' "${PROJECT_DIR}/.env"; then
  echo "CLEANUP_ADMIN_TOKEN must be set in ${PROJECT_DIR}/.env before enabling the service." >&2
  exit 2
fi

install -m 0644 "${UNIT_SOURCE}" "${UNIT_TARGET}"
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
systemctl --no-pager --full status "${SERVICE_NAME}"
