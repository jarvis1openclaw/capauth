<?php

declare(strict_types=1);

return [
    'routes' => [
        // ── Login page (alternative-login button target) ─────────────────────
        [
            'name'    => 'login#showLogin',
            'url'     => '/login',
            'verb'    => 'GET',
        ],

        // ── Challenge / verify flow (primary passwordless login) ─────────────
        // js/login.js posts to /apps/capauth/v1/* — keep that prefix.
        [
            'name'    => 'login#challenge',
            'url'     => '/v1/challenge',
            'verb'    => 'POST',
        ],
        [
            'name'    => 'login#nonceStatus',
            'url'     => '/v1/nonce/{nonce}/status',
            'verb'    => 'GET',
        ],
        [
            'name'    => 'login#verify',
            'url'     => '/v1/verify',
            'verb'    => 'POST',
        ],

        // ── Token validation endpoint ────────────────────────────────────────
        // Used by external services (Nextcloud apps, CLI tools) to validate a
        // CapAuth Bearer token. Returns the identity claims on success.
        [
            'name'    => 'token#validate',
            'url'     => '/token/validate',
            'verb'    => 'POST',
        ],
        [
            'name'    => 'token#whoami',
            'url'     => '/token/whoami',
            'verb'    => 'GET',
        ],
    ],
];
