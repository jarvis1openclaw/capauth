<?php

declare(strict_types=1);

namespace OCA\CapAuth\Service;

use OCP\ICache;
use OCP\ICacheFactory;
use OCP\IConfig;

/**
 * Issues and validates CapAuth challenge nonces.
 *
 * Nonces are stored in the Nextcloud DISTRIBUTED cache with a TTL.
 * Once consumed a nonce is marked as used so replay is impossible.
 *
 * IMPORTANT: the challenge runs PRE-LOGIN (no authenticated user), so we must
 * use a NON-user-scoped cache. Injecting OCP\ICache directly resolves to the
 * per-user cache and throws "Can't get cache storage, user not logged in" on
 * the public passwordless-login routes. We build a distributed cache via
 * ICacheFactory instead (memcache/redis when configured; an isAvailable()
 * guard falls back to a local cache otherwise).
 */
class ChallengeService {
    private const CACHE_PREFIX  = 'capauth_nonce_';
    private const DEFAULT_TTL   = 120; // seconds

    private readonly ICache $cache;

    public function __construct(
        private readonly IConfig $config,
        ICacheFactory $cacheFactory,
    ) {
        // Distributed cache works without a logged-in user; falls back to a
        // local cache when no distributed backend is configured.
        $this->cache = $cacheFactory->isAvailable()
            ? $cacheFactory->createDistributed('capauth_nonce')
            : $cacheFactory->createLocal('capauth_nonce');
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    private function ttl(): int {
        return (int) $this->config->getAppValue('capauth', 'nonce_ttl', (string) self::DEFAULT_TTL);
    }

    private function cacheKey(string $nonce): string {
        return self::CACHE_PREFIX . $nonce;
    }

    private function generateUuidV4(): string {
        $data    = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Issue a new challenge for the given fingerprint.
     *
     * Origin-binding (Tier A): the server ASSERTS its own canonical RP origin
     * into the issued record so the client signs over it (CAPAUTH_NONCE_V2) and
     * the verifier can confirm it matches the configured allowed origin on
     * return. When $origin is '' the legacy V1 (origin-less) payload is used so
     * existing clients keep working during the dual-accept migration window.
     *
     * @return array{nonce:string, client_nonce_echo:string, issued_at:string,
     *               expires_at:string, service:string, origin:string,
     *               fingerprint:string, used:bool}
     */
    public function issue(string $fingerprint, string $service, string $clientNonce = '', string $origin = ''): array {
        $fp        = strtoupper(trim($fingerprint));
        $nonce     = $this->generateUuidV4();
        $issuedAt  = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(\DateTimeInterface::ATOM);
        $ttl       = $this->ttl();
        $expiresAt = (new \DateTimeImmutable("now +{$ttl} seconds", new \DateTimeZone('UTC')))->format(\DateTimeInterface::ATOM);
        $echo      = $clientNonce !== '' ? $clientNonce : base64_encode(random_bytes(16));

        $record = [
            'nonce'             => $nonce,
            'client_nonce_echo' => $echo,
            'issued_at'         => $issuedAt,
            'expires_at'        => $expiresAt,
            'service'           => $service,
            'origin'            => $origin,
            'fingerprint'       => $fp,
            'used'              => false,
        ];

        $this->cache->set($this->cacheKey($nonce), $record, $ttl);

        return $record;
    }

    /**
     * Consume a nonce. Returns [true, ''] on success or [false, error_code].
     *
     * @return array{0:bool, 1:string}
     */
    public function consume(string $nonce, string $fingerprint): array {
        $fp  = strtoupper(trim($fingerprint));
        $rec = $this->cache->get($this->cacheKey($nonce));

        if ($rec === null || !is_array($rec)) {
            return [false, 'invalid_nonce', null];
        }
        if ($rec['used'] === true) {
            return [false, 'invalid_nonce', null];
        }
        if (strtoupper($rec['fingerprint']) !== $fp) {
            return [false, 'invalid_nonce', null];
        }
        if (new \DateTimeImmutable() > new \DateTimeImmutable($rec['expires_at'])) {
            return [false, 'invalid_nonce', null];
        }

        // Mark consumed.
        $rec['used'] = true;
        $this->cache->set($this->cacheKey($nonce), $rec, 60);

        // Return the (pre-consume) record so the caller can rebuild the exact
        // canonical challenge the client signed — the authoritative source,
        // independent of the PHP session (which is unreliable pre-login).
        return [true, '', $rec];
    }

    /**
     * Inspect a nonce without consuming it. Returns the cache record or null.
     */
    public function peek(string $nonce): ?array {
        $rec = $this->cache->get($this->cacheKey($nonce));
        return is_array($rec) ? $rec : null;
    }

    // ── Canonical payload helpers ────────────────────────────────────────────

    /**
     * Builds the deterministic plaintext that the client signs for nonce auth.
     *
     * When $origin is a non-empty string the V2 (origin-bound) payload is
     * produced with the origin line between client_nonce and timestamp; when
     * $origin is null the legacy V1 payload is produced (dual-accept migration).
     * The byte layout MUST match the Python, JS and stage implementations — a
     * shared cross-impl test vector asserts this.
     */
    public function canonicalNoncePayload(
        string $nonce,
        string $clientNonce,
        string $issuedAt,
        string $service,
        string $expiresAt,
        ?string $origin = null,
    ): string {
        if ($origin === null) {
            return implode("\n", [
                'CAPAUTH_NONCE_V1',
                "nonce={$nonce}",
                "client_nonce={$clientNonce}",
                "timestamp={$issuedAt}",
                "service={$service}",
                "expires={$expiresAt}",
            ]);
        }
        return implode("\n", [
            'CAPAUTH_NONCE_V2',
            "nonce={$nonce}",
            "client_nonce={$clientNonce}",
            "origin={$origin}",
            "timestamp={$issuedAt}",
            "service={$service}",
            "expires={$expiresAt}",
        ]);
    }

    /**
     * Builds the deterministic plaintext for signed identity claims.
     */
    public function canonicalClaimsPayload(
        string $fingerprint,
        string $nonce,
        array  $claims,
    ): string {
        ksort($claims);
        $claimsJson = json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return implode("\n", [
            'CAPAUTH_CLAIMS_V1',
            "fingerprint={$fingerprint}",
            "nonce={$nonce}",
            "claims={$claimsJson}",
        ]);
    }
}
