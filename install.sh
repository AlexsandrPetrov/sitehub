#!/usr/bin/env bash
# SiteHub installer for Debian / Ubuntu.
#   curl -fsSL https://raw.githubusercontent.com/AlexsandrPetrov/sitehub/main/install.sh | sudo bash
# or from a cloned repository:  sudo ./install.sh
# Variables: PORT (first install only, default 8080), ADMIN_USER (default admin), REPO, BRANCH
set -euo pipefail

REPO="${REPO:-https://github.com/AlexsandrPetrov/sitehub.git}"
BRANCH="${BRANCH:-main}"
APP=/opt/sitehub
DATA=/var/lib/sitehub
PORT="${PORT:-8080}"
ADMIN_USER="${ADMIN_USER:-admin}"

[ "$(id -u)" = "0" ] || { echo "Запустите от root (sudo)"; exit 1; }

echo "==> Пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git certbot ca-certificates >/dev/null

echo "==> Пользователь sitehub"
id sitehub >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin sitehub

echo "==> Код приложения в $APP"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$SRC" ] && [ -f "$SRC/sitehub/app.py" ] && [ "$SRC" != "$APP" ]; then
  mkdir -p "$APP"
  cp -a "$SRC/sitehub" "$SRC/templates" "$SRC/static" "$SRC/deploy" "$SRC/requirements.txt" "$APP/"
elif [ -d "$APP/.git" ]; then
  git -C "$APP" fetch -q origin "$BRANCH" && git -C "$APP" reset -q --hard "origin/$BRANCH"
elif [ ! -f "$APP/sitehub/app.py" ]; then
  git clone -q -b "$BRANCH" "$REPO" "$APP"
fi

echo "==> Python-окружение"
[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"

echo "==> Данные в $DATA"
mkdir -p "$DATA"
chown -R sitehub:sitehub "$DATA"
chmod 750 "$DATA"

install -m 0644 "$APP/deploy/sitehub.service" /etc/systemd/system/sitehub.service
install -m 0755 "$APP/deploy/sitehub-cli" /usr/local/bin/sitehub
mkdir -p /etc/systemd/system/sitehub.service.d
if systemd-run --quiet --wait --collect -p ProtectSystem=strict -p PrivateTmp=true /bin/true >/dev/null 2>&1; then
  install -m 0644 "$APP/deploy/hardening.conf" /etc/systemd/system/sitehub.service.d/hardening.conf
  echo "==> Песочница systemd включена"
else
  rm -f /etc/systemd/system/sitehub.service.d/hardening.conf
  echo "==> Песочница systemd недоступна (непривилегированный контейнер) — пропускаю"
fi

FIRST=0
if [ ! -f "$DATA/sitehub.db" ]; then
  FIRST=1
  runuser -u sitehub -- env SITEHUB_DATA="$DATA" PYTHONPATH="$APP" "$APP/venv/bin/python" -c \
    "from sitehub import config, db; db.init(); config.set_many({'port': '$PORT'})"
fi
ADMIN_LINE=""
if ! sitehub users | grep -q .; then
  ADMIN_LINE="$(sitehub create-admin "$ADMIN_USER")"
fi

systemctl daemon-reload
systemctl enable -q sitehub
systemctl restart sitehub
sleep 2

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
CUR_PORT="$(sitehub show | awk '$1=="port"{print $3}')"
echo
echo "================================================================"
systemctl is-active --quiet sitehub && echo " SiteHub запущен" || echo " ВНИМАНИЕ: сервис не запустился — journalctl -u sitehub"
echo " Адрес:  http://${IP:-<ip>}:${CUR_PORT}"
[ -n "$ADMIN_LINE" ] && echo " $ADMIN_LINE"
[ "$FIRST" = "1" ] && echo " Смените пароль и включите 2FA в профиле после первого входа."
echo " Управление из консоли: sitehub --help"
echo "================================================================"
