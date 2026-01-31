<?php

/**
 * MBT: логика выдачи подписки не-админам (список профилей, конфиг, кнопки).
 * Подключается из bot.php в двух местах: auth() и action().
 * При обновлении bot.php из другого источника нужно только вернуть 2 вызова:
 *   1) в auth() для не-админа: if (!/verifySub/) { require_once __DIR__.'/mbt_verify_user.php'; mbt_verify_user_show($this); exit; }
 *   2) в action(): case /verifySub: require_once ...; mbt_verify_user_callback($this, $m['arg']??'list'); break;
 */

declare(strict_types=1);

function mbt_verify_user_get_found_indexes(Bot $bot): array
{
    $clients = $bot->getXray()['inbounds'][0]['settings']['clients'] ?? [];
    $foundIndexes = [];
    foreach ($clients as $i => $user) {
        if (isset($user['email']) && preg_match('/\[tg_(\d+)]/i', $user['email'], $m) && (string)$m[1] === (string)$bot->input['from']) {
            $foundIndexes[] = $i;
        }
    }
    return $foundIndexes;
}

function mbt_verify_user_traffic_line(Bot $bot, int $clientIndex): string
{
    try {
        $st = $bot->getXrayStats();
        if (empty($st['users'][$clientIndex])) {
            return '';
        }
        $u = $st['users'][$clientIndex];
        $down = ($u['global']['download'] ?? 0) + ($u['session']['download'] ?? 0);
        $up   = ($u['global']['upload'] ?? 0) + ($u['session']['upload'] ?? 0);
        return "📊 <b>Трафик:</b> ↓ " . $bot->getBytes($down) . "  ·  ↑ " . $bot->getBytes($up);
    } catch (\Throwable $e) {
        return '';
    }
}

function mbt_verify_user_config_text(Bot $bot, int $index): string
{
    $foundIndexes = mbt_verify_user_get_found_indexes($bot);
    if (!isset($foundIndexes[$index])) {
        return '';
    }
    $esc = fn(string $s) => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $clients = $bot->getXray()['inbounds'][0]['settings']['clients'] ?? [];
    $clientIdx = $foundIndexes[$index];
    $c = $clients[$clientIdx];
    $email = $c['email'];
    $pac = $bot->getPacConf();
    $domain = $bot->getDomain($pac['transport'] != 'Reality');
    $scheme = empty($bot->nginxGetTypeCert()) ? 'http' : 'https';
    $hash = $bot->getHashBot();
    $siPayload = base64_encode(serialize(['h' => $hash, 't' => 'si', 's' => $c['id']]));
    $si = "{$scheme}://{$domain}/pac{$hash}/{$siPayload}";
    $importUrl = "{$scheme}://{$domain}/pac{$hash}?t=si&r=si&s={$c['id']}#" . rawurlencode($email);
    $windowsUrl = "{$scheme}://{$domain}/pac{$hash}?t=si&r=w&s={$c['id']}";
    $emailLower = strtolower($email);
    $isOpenWrt = str_contains($emailLower, '[openwrt]');
    $isWindows = str_contains($emailLower, '[windows]');
    $isTablet = str_contains($emailLower, '[tablet]');
    $isMac = str_contains($emailLower, '[mac]');
    $cleanName = preg_replace('/^\[tg_\d+]\_?/', '', $email) ?: "Профиль " . ($index + 1);
    $trafficLine = mbt_verify_user_traffic_line($bot, $clientIdx);
    $lines = [];
    $lines[] = "👤 <b>Профиль:</b> <code>{$esc($cleanName)}</code>";
    if ($trafficLine !== '') {
        $lines[] = $trafficLine;
    }
    $lines[] = "";
    $lines[] = "━━━ <b>Инструкция по устройству</b> ━━━";
    $lines[] = "";
    if ($isOpenWrt) {
        $lines[] = "📡 <b>Роутер (OpenWRT)</b>";
        $lines[] = "• Установите: <a href=\"https://github.com/ang3el7z/luci-app-singbox-ui\">luci-app-singbox-ui</a>";
        $lines[] = "• Конфиг-сервер:";
        $lines[] = "<code>{$esc($si)}</code>";
    } elseif ($isWindows) {
        $lines[] = "🖥 <b>Windows 10/11</b>";
        $lines[] = "• Скачать: <a href=\"{$esc($windowsUrl)}\">sing-box для Windows</a>";
        $lines[] = "• Распаковать в <code>C:\\serviceBot</code> (путь только латиницей)";
        $lines[] = "• Запустить <code>install</code>, затем <code>start</code>";
        $lines[] = "• Проверка: <code>status</code>";
    } elseif ($isTablet) {
        $lines[] = "📱 <b>Планшет (Android / iOS)</b>";
        $lines[] = "• Установить sing-box: <a href=\"https://play.google.com/store/apps/details?id=io.nekohasekai.sfa\">Google Play</a> / <a href=\"https://apps.apple.com/us/app/sing-box-vt/id6673731168\">App Store</a>";
        $lines[] = "• Импорт: <a href=\"{$esc($importUrl)}\">import://sing-box</a>";
        $lines[] = "• Import → Create → Dashboard → Start";
    } elseif ($isMac) {
        $lines[] = "💻 <b>Mac</b>";
        $lines[] = "• Установить sing-box: <a href=\"https://apps.apple.com/us/app/sing-box-vt/id6673731168\">App Store</a>";
        $lines[] = "• Импорт: <a href=\"{$esc($importUrl)}\">import://sing-box</a>";
        $lines[] = "• Import → Create → Dashboard → Start";
    } else {
        $lines[] = "📱 <b>Телефон (Android / iOS)</b>";
        $lines[] = "• Установить sing-box: <a href=\"https://play.google.com/store/apps/details?id=io.nekohasekai.sfa\">Google Play</a> / <a href=\"https://apps.apple.com/us/app/sing-box-vt/id6673731168\">App Store</a>";
        $lines[] = "• Импорт: <a href=\"{$esc($importUrl)}\">import://sing-box</a>";
        $lines[] = "• Import → Create → Dashboard → Start";
    }
    $lines[] = "";
    $lines[] = "🔒 <b>Ограничения</b>";
    $lines[] = "• Один конфиг — одно устройство";
    $lines[] = "• Передача конфига посторонним — <b>бан навсегда</b>";
    $lines[] = "• Не использовать на нескольких устройствах одновременно";
    $lines[] = "";
    $lines[] = "⚠️ Нажмите кнопку <b>Обновить</b> ниже для актуальной конфигурации.";
    return implode("\n", $lines);
}

function mbt_verify_user_list_data(Bot $bot): array
{
    $foundIndexes = mbt_verify_user_get_found_indexes($bot);
    if (empty($foundIndexes)) {
        return ['text' => '', 'keyboard' => []];
    }
    $clients = $bot->getXray()['inbounds'][0]['settings']['clients'] ?? [];
    $rows = [];
    foreach ($foundIndexes as $i => $idx) {
        $email = $clients[$idx]['email'] ?? '';
        $cleanName = preg_replace('/^\[tg_\d+]\_?/', '', $email) ?: "Профиль " . ($i + 1);
        $rows[] = [['text' => $cleanName, 'callback_data' => "/verifySub $i"]];
    }
    $header = "📋 <b>Ваши профили</b>\n\nВыберите профиль — откроется инструкция и ссылки для подключения.";
    return ['text' => $header, 'keyboard' => $rows];
}

/**
 * Точка входа для не-админа: один профиль — сразу конфиг, несколько — список кнопок.
 */
function mbt_verify_user_show(Bot $bot): void
{
    $foundIndexes = mbt_verify_user_get_found_indexes($bot);
    if (empty($foundIndexes)) {
        return;
    }
    try {
        if (count($foundIndexes) === 1) {
            $text = mbt_verify_user_config_text($bot, 0);
            $keyboard = [[['text' => "🔄 Обновить", 'callback_data' => '/verifySub refresh']]];
            $bot->send($bot->input['chat'], $text, 0, $keyboard, false, 'HTML', false, true);
        } else {
            $list = mbt_verify_user_list_data($bot);
            $bot->send($bot->input['chat'], $list['text'], 0, $list['keyboard'], false, 'HTML', false, true);
        }
    } catch (\Throwable $e) {
        $bot->send($bot->input['chat'], "verifyUser: " . $e->getMessage(), $bot->input['message_id']);
    }
}

/**
 * Обработка нажатий кнопок подписки: список (list), выбор профиля (N), обновить (refresh).
 */
function mbt_verify_user_callback(Bot $bot, ?string $arg): void
{
    $cid = $bot->input['callback_id'] ?? null;
    $answer = function ($msg = null) use ($bot, $cid) {
        if ($cid !== null) {
            $bot->answer($cid, $msg);
        }
    };
    try {
        $foundIndexes = mbt_verify_user_get_found_indexes($bot);
        if (empty($foundIndexes)) {
            $answer('Нет конфигов.');
            return;
        }
        $chat = $bot->input['chat'];
        $messageId = (int) $bot->input['message_id'];
        $arg = trim((string)$arg);
        if ($arg === 'list' || $arg === '') {
            $list = mbt_verify_user_list_data($bot);
            $text = $list['text'] ?: '📋 Ваши профили';
            if (mb_strlen($text, 'UTF-8') > 4096) {
                $text = mb_substr($text, 0, 4093, 'UTF-8') . '...';
            }
            $bot->update($chat, $messageId, $text, $list['keyboard']);
            $answer();
            return;
        }
        if (preg_match('/^refresh(?:\s+(\d+))?$/', $arg, $m)) {
            $index = isset($m[1]) ? (int)$m[1] : 0;
            if (!isset($foundIndexes[$index])) {
                $index = 0;
            }
        } elseif (preg_match('/^\d+$/', $arg)) {
            $index = (int)$arg;
            if (!isset($foundIndexes[$index])) {
                $index = 0;
            }
        } else {
            $answer();
            return;
        }
        $text = mbt_verify_user_config_text($bot, $index);
        if ($text === '') {
            $text = '👤 Профиль #' . ($index + 1) . "\n\nНет данных.";
        }
        if (mb_strlen($text, 'UTF-8') > 4096) {
            $text = mb_substr($text, 0, 4093, 'UTF-8') . '...';
        }
        $keyboard = [];
        if (count($foundIndexes) > 1) {
            $keyboard[] = [['text' => "← Назад", 'callback_data' => '/verifySub list'], ['text' => "🔄 Обновить", 'callback_data' => "/verifySub refresh $index"]];
        } else {
            $keyboard[] = [['text' => "🔄 Обновить", 'callback_data' => '/verifySub refresh']];
        }
        $r = $bot->update($chat, $messageId, $text, $keyboard);
        $answer();
        if (!empty($r['ok']) && $r['ok'] === true) {
            return;
        }
        if (!empty($r['description']) && (stripos($r['description'], 'not modified') !== false || stripos($r['description'], 'message is the same') !== false)) {
            return;
        }
        $bot->send($bot->input['chat'], $text, 0, $keyboard, false, 'HTML', false, false, true);
    } catch (\Throwable $e) {
        $answer('Ошибка');
        $bot->send($bot->input['chat'], "Ошибка: " . $e->getMessage(), $bot->input['message_id']);
    }
}
