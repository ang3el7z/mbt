<?php

/**
 * Шаблон внедрения verifyUser в авторизацию бота.
 *
 * ИНСТРУКЦИЯ:
 * 1. В методе auth() (или аналоге), после проверки/нормализации $c['admin'], вставьте:
 *
 *    elseif (!in_array($this->input['from'], $c['admin'])) {
 *        $this->verifyUser();
 *        exit;
 *    }
 *
 * 2. Вариант A: в классе бота добавьте:  use VerifyUserAuth;
 *    Вариант B: скопируйте методы из трейта VerifyUserAuth в свой класс.
 *
 * 3. В классе должны быть: $this->input, $this->send(), getXray(), getPacConf(),
 *    getDomain(), nginxGetTypeCert(), getHashBot().
 */
trait VerifyUserAuth
{
    private function esc(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private function href(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public function verifyUser(): void
    {
    $clients = $this->getXray()['inbounds'][0]['settings']['clients'] ?? [];

    $foundIndexes = [];
    foreach ($clients as $i => $user) {
        if (
            isset($user['email']) &&
            preg_match('/\[tg_(\d+)]/i', $user['email'], $m) &&
            (string)$m[1] === (string)$this->input['from']
        ) {
            $foundIndexes[] = $i;
        }
    }

    if (empty($foundIndexes)) {
        return;
    }

    $this->send($this->input['chat'], "verifyUser: найдено совпадений: " . count($foundIndexes) . " → [" . implode(',', $foundIndexes) . "]", $this->input['message_id']);

    $pac    = $this->getPacConf();
    $domain = $this->getDomain($pac['transport'] != 'Reality');
    $scheme = empty($this->nginxGetTypeCert()) ? 'http' : 'https';
    $hash   = $this->getHashBot();

    $messageParts = [];

    foreach ($foundIndexes as $index) {
        $c     = $clients[$index];
        $email = $c['email'];

        $siPayload = base64_encode(serialize([
            'h' => $hash,
            't' => 'si',
            's' => $c['id'],
        ]));
        $si = "{$scheme}://{$domain}/pac{$hash}/{$siPayload}";

        $importUrl  = "{$scheme}://{$domain}/pac{$hash}?t=si&r=si&s={$c['id']}#" . rawurlencode($email);
        $windowsUrl = "{$scheme}://{$domain}/pac{$hash}?t=si&r=w&s={$c['id']}";

        $emailLower = strtolower($email);
        $isOpenWrt  = str_contains($emailLower, '[openwrt]');
        $isWindows  = str_contains($emailLower, '[windows]');
        $isTablet   = str_contains($emailLower, '[tablet]');
        $isMac      = str_contains($emailLower, '[mac]');

        $textParts = [];

        $cleanName = preg_replace('/^\[tg_\d+]\_?/', '', $email);
        $textParts[] = "🧾 <b>Конфиг для:</b> <code>{$this->esc($cleanName)}</code>";

        if ($isOpenWrt) {
            $textParts[] =
                "📡 <b>Роутер (OpenWRT)</b>\n"
                . "⚠️ Только для OpenWRT.\n"
                . "1. Установите интерфейс: <a href=\"https://github.com/ang3el7z/luci-app-singbox-ui\">GitHub</a>\n"
                . "2. Используйте следующий конфиг-сервер:\n"
                . "<pre><code>{$this->esc($si)}</code></pre>\n"
                . "✅ Подходит для ручного импорта.";
        } elseif ($isWindows) {
            $textParts[] =
                "🖥 <b>Windows</b>\n"
                . "⚠️ Только для Windows 10/11.\n"
                . "1. Скачайте клиент: <a href=\"{$this->href($windowsUrl)}\">sing-box для Windows</a>\n"
                . "2. Распакуйте, например, в <code>C:\\serviceBot</code> ⚠️ <i>Имя пути только на англ.!</i>\n"
                . "3. Запустите <code>install</code>, затем <code>start</code>.\n"
                . "4. Проверка подключения: выполните <code>status</code>\n"
                . "✅ Работает автоматически, включая при перезагрузке.";
        } elseif ($isTablet) {
            $textParts[] =
                "📱 <b>Планшет (Android / iOS)</b>\n"
                . "⚠️ Только для Android / iOS.\n"
                . "1. Установите приложение <b>sing-box</b>:\n"
                . "• <a href=\"https://play.google.com/store/apps/details?id=io.nekohasekai.sfa&hl=ru&pli=1\">Play Store</a>\n"
                . "• <a href=\"https://apps.apple.com/ru/app/sing-box-vt/id6673731168?l=en-ru\">App Store</a>\n"
                . "2. Перейдите по ссылке: <a href=\"{$this->href($importUrl)}\">import://sing-box</a>\n"
                . "3. Нажмите <b>Import</b> → <b>Create</b>.\n"
                . "4. Перейдите в <b>Dashboard</b> и нажмите <b>Start</b>.\n"
                . "✅ Всё готово для использования.";
        } elseif ($isMac) {
            $textParts[] =
                "💻 <b>Mac</b>\n"
                . "1. Установите приложение <b>sing-box</b>\n"
                . "• <a href=\"https://apps.apple.com/ru/app/sing-box-vt/id6673731168?l=en-ru\">App Store</a>\n"
                . "2. Перейдите по ссылке: <a href=\"{$this->href($importUrl)}\">import://sing-box</a>\n"
                . "3. Нажмите <b>Import</b> → <b>Create</b>.\n"
                . "4. Перейдите в <b>Dashboard</b> и нажмите <b>Start</b>.\n"
                . "✅ Всё готово для использования.";
        } else {
            $textParts[] =
                "📱 <b>Телефон (Android / iOS)</b>\n"
                . "1. Установите приложение <b>sing-box</b>:\n"
                . "• <a href=\"https://play.google.com/store/apps/details?id=io.nekohasekai.sfa&hl=ru&pli=1\">Play Store</a>\n"
                . "• <a href=\"https://apps.apple.com/ru/app/sing-box-vt/id6673731168?l=en-ru\">App Store</a>\n"
                . "2. Перейдите по ссылке: <a href=\"{$this->href($importUrl)}\">import://sing-box</a>\n"
                . "3. Нажмите <b>Import</b> → <b>Create</b>.\n"
                . "4. Перейдите в <b>Dashboard</b> и нажмите <b>Start</b>.\n"
                . "✅ Всё готово для использования.";
        }

        $textParts[] = "🔒 <b>Ограничения</b>\n"
            . "• 1 конфиг = 1 устройство\n"
            . "• Попытка поделиться конфигом с посторонними человеком ➜ <b>бан навсегда</b>\n"
            . "• Нельзя использовать одновременно на несколько устройств";

        $messageParts[] = implode("\n\n", $textParts);
    }

    $messageParts[] = "<b>⚠️ Перед использованием обязательно нажмите кнопку ниже для получения актуальной конфигурации ⚠️</b>";

    $keyboard = [
        [
            ['text' => "🔄 Обновить", 'callback_data' => "/menu"],
        ],
    ];

    try {
        $this->send(
            $this->input['chat'],
            implode("\n\n———————————————\n\n", $messageParts),
            $this->input['message_id'],
            $keyboard,
            false,
            'HTML',
            false,
            true
        );
    } catch (\Throwable $e) {
        $this->send($this->input['chat'], "verifyUser: ошибка отправки: " . $e->getMessage(), $this->input['message_id']);
    }
    }
}
