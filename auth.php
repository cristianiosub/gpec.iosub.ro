<?php
/**
 * GPeC Auth — include la inceputul oricarei pagini protejate
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function requireLogin(): void {
    if (empty($_SESSION['gpec_user'])) {
        $back = urlencode($_SERVER['REQUEST_URI'] ?? '');
        header('Location: login' . ($back ? "?next={$back}" : ''));
        exit;
    }
}

function currentUser(): array {
    return $_SESSION['gpec_user'] ?? [];
}

function isLoggedIn(): bool {
    return !empty($_SESSION['gpec_user']);
}
