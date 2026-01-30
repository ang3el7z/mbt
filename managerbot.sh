#!/bin/bash

# =============================================================================
# MANAGER BOT — единая точка входа и все настройки
# Без параметров: интерактивное меню по цифрам
# С параметром: managerbot.sh -r или -restart | -s или -swap | -suc или -stop-unwanted-containers
# =============================================================================

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir="$(cd "$(dirname "$0")" && pwd)"

# --- Настройки ---
VPNBOT_DIR="${VPNBOT_DIR:-/root/vpnbot}"
SWAPFILE="${SWAPFILE:-/swapfile}"
SWAPSIZE="${SWAPSIZE:-1536M}"
UNWANTED_CONTAINERS="${UNWANTED_CONTAINERS:-mtproto wireguard1 shadowsocks openconnect wireguard naive hysteria proxy dnstt adguard}"

# =============================================================================

usage() {
  echo -e "Использование: ${green}$(basename "$0")${plain} [команда]"
  echo ""
  echo "Без параметров — интерактивное меню."
  echo ""
  echo "Команды:"
  echo -e "  ${green}-restart${plain}, ${green}-r${plain}              Перезапуск бота (make r)"
  echo -e "  ${green}-swap${plain}, ${green}-s${plain}              Создать и включить swap (1.5 GB)"
  echo -e "  ${green}-stop-unwanted-containers${plain}, ${green}-suc${plain}   Остановить ненужные Docker-контейнеры"
  echo -e "  ${green}-add-crontab-stop-containers${plain} Добавить в crontab задачу остановки контейнеров после перезагрузки"
  echo -e "  ${green}-h${plain}, ${green}--help${plain}               Справка"
}

# Проверка root (для swap и docker)
check_root() {
  [[ $EUID -ne 0 ]] && echo -e "${red}Ошибка:${plain} эта операция требует прав root. Запустите с sudo." && exit 1
}

# --- Действия ---

run_restart() {
  echo -e "${blue}Перезапуск бота...${plain}"
  if [[ ! -d "$VPNBOT_DIR" ]]; then
    echo -e "${red}Каталог не найден: $VPNBOT_DIR${plain}"
    exit 1
  fi
  (cd "$VPNBOT_DIR" && make r) || { echo -e "${red}Ошибка make r${plain}"; exit 1; }
  echo -e "${green}Готово.${plain}"
}

run_swap() {
  check_root
  echo -e "${blue}Настройка swap...${plain}"
  if swapon --show | grep -q "$SWAPFILE"; then
    echo -e "${green}Swap уже активен.${plain}"
    return 0
  fi
  SWAP_MB="${SWAPSIZE%M}"
  if ! fallocate -l "$SWAPSIZE" "$SWAPFILE" 2>/dev/null; then
    dd if=/dev/zero of="$SWAPFILE" bs=1M count="${SWAP_MB:-1536}"
  fi
  chmod 600 "$SWAPFILE"
  mkswap "$SWAPFILE"
  swapon "$SWAPFILE"
  grep -qF "$SWAPFILE" /etc/fstab || echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  sysctl vm.swappiness=10 2>/dev/null || true
  grep -qF 'vm.swappiness=10' /etc/sysctl.conf 2>/dev/null || echo 'vm.swappiness=10' >> /etc/sysctl.conf
  echo -e "${green}Swap создан и активирован:${plain}"
  swapon --show
  free -m
}

run_stop_containers() {
  check_root
  echo -e "${blue}Остановка ненужных контейнеров...${plain}"
  read -ra patterns <<< "$UNWANTED_CONTAINERS"
  ALL_CONTAINERS=$(docker ps -a --format "{{.Names}}" 2>/dev/null) || { echo -e "${yellow}Docker недоступен или контейнеров нет.${plain}"; return 0; }
  for container in $ALL_CONTAINERS; do
    for pattern in "${patterns[@]}"; do
      if [[ "$container" == *"$pattern"* ]]; then
        STATUS=$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null)
        if [[ "$STATUS" == "exited" || "$STATUS" == "created" || "$STATUS" == "dead" ]]; then
          echo -e "${yellow}Контейнер '$container' уже остановлен (статус: $STATUS).${plain}"
        elif [[ "$STATUS" == "running" ]]; then
          echo -e "${blue}Останавливаю: $container${plain}"
          docker stop "$container" >/dev/null 2>&1
        else
          echo -e "${yellow}Контейнер '$container' в состоянии '$STATUS', пропускаю.${plain}"
        fi
        break
      fi
    done
  done
  echo -e "${green}Ненужные контейнеры обработаны.${plain}"
}

# Добавить в crontab задачу: через 5 мин после reboot — stop-unwanted-containers с логом
run_add_crontab_stop_containers() {
  local line="@reboot (sleep 300 && cd $cur_dir && ./managerbot.sh -suc) >> /var/log/docker-cleanup.log 2>&1"
  if crontab -l 2>/dev/null | grep -qF "managerbot.sh -suc"; then
    echo -e "${yellow}Задача уже есть в crontab.${plain}"
    return 0
  fi
  (crontab -l 2>/dev/null; echo "$line") | crontab -
  echo -e "${green}В crontab добавлено:${plain} $line"
}

# --- Интерактивное меню ---

# После выполнения команды: 0 — выйти, 1 — вернуться в меню. Возврат: 0 = в меню, 1 = выйти
prompt_back_or_exit() {
  echo ""
  echo -e "${yellow}0${plain} — Выход    ${yellow}1${plain} — Назад в меню"
  echo -n "Выберите [0/1]: "
  read -r r
  if [[ "$r" == "0" ]]; then
    echo -e "${green}Выход.${plain}"
    return 1
  fi
  return 0
}

show_menu() {
  while true; do
    echo ""
    echo -e "${green}═══════════════════════════════════════${plain}"
    echo -e "${green}           MANAGER BOT                ${plain}"
    echo -e "${green}═══════════════════════════════════════${plain}"
    echo -e "  ${blue}1.${plain} Перезапуск бота (make r)"
    echo -e "  ${blue}2.${plain} Создать swap 1.5 GB"
    echo -e "  ${blue}3.${plain} Остановить ненужные Docker-контейнеры"
    echo -e "  ${blue}4.${plain} Добавить в crontab задачу остановки контейнеров после перезагрузки"
    echo -e "  ${blue}0.${plain} Выход"
    echo -e "${green}═══════════════════════════════════════${plain}"
    echo -n "Выберите действие [0-4]: "
    read -r choice
    case "$choice" in
      1) run_restart; prompt_back_or_exit || exit 0 ;;
      2) run_swap; prompt_back_or_exit || exit 0 ;;
      3) run_stop_containers; prompt_back_or_exit || exit 0 ;;
      4) run_add_crontab_stop_containers; prompt_back_or_exit || exit 0 ;;
      0) echo -e "${green}Выход.${plain}"; exit 0 ;;
      *) echo -e "${red}Неверный выбор.${plain}" ;;
    esac
  done
}

# =============================================================================
# Точка входа
# =============================================================================

cmd="${1:-}"
case "${cmd#--}" in
  -h|help|"")
    if [[ -z "$cmd" ]]; then
      show_menu
    else
      usage
      exit 0
    fi
    ;;
  -r|restart)
    run_restart
    ;;
  -s|swap)
    run_swap
    ;;
  -suc|-stop-unwanted-containers)
    run_stop_containers
    ;;
  -add-crontab-stop-containers)
    run_add_crontab_stop_containers
    ;;
  *)
    echo -e "${red}Неизвестная команда: $cmd${plain}"
    usage
    exit 1
    ;;
esac
