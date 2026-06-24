<?php

declare(strict_types=1);

namespace OCA\CapAuth\Service;

use OCP\ILogger;

/**
 * Verifies PGP signatures produced by CapAuth clients.
 *
 * Uses the PHP gnupg extension when available; falls back to shelling out
 * to gpg2/gpg via proc_open for environments where the extension is absent.
 */
class VerifierService {
    public function __construct(
        private readonly ILogger $logger,
    ) {}

    // ── Canonical payload builders ───────────────────────────────────────────

    /**
     * Build the canonical nonce payload (V1 legacy or V2 origin-bound).
     *
     * Pass $origin === null for the legacy V1 payload (dual-accept migration);
     * pass a non-empty origin string for the V2 origin-bound payload. The byte
     * layout MUST match ChallengeService, the Python verifier, the login JS and
     * the stage signers — a shared cross-impl test vector asserts this.
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
     * Normalise an origin for equality comparison (lowercase scheme+host,
     * strip a trailing slash; port preserved). Does NOT change signed bytes.
     */
    public static function normalizeOrigin(string $origin): string {
        $o = rtrim(trim($origin), '/');
        if (str_contains($o, '://')) {
            [$scheme, $rest] = explode('://', $o, 2);
            return strtolower($scheme) . '://' . strtolower($rest);
        }
        return strtolower($o);
    }

    /**
     * Tier-A origin assertion check.
     *
     * @param string|null $issuedOrigin    Origin bound into the signed payload,
     *                                      or null for a legacy V1 challenge.
     * @param string[]    $allowedOrigins  RP-configured allowed origins.
     * @param bool        $requireBinding  When true, reject V1 (origin-less).
     * @return array{0:bool, 1:string}     [ok, error_code]
     */
    public function checkOrigin(?string $issuedOrigin, array $allowedOrigins, bool $requireBinding = false): array {
        if ($issuedOrigin === null || $issuedOrigin === '') {
            if ($requireBinding) {
                return [false, 'v1_rejected'];
            }
            return [true, ''];
        }
        $allowedNorm = array_map([self::class, 'normalizeOrigin'], array_filter($allowedOrigins, fn($o) => $o !== ''));
        if (in_array(self::normalizeOrigin($issuedOrigin), $allowedNorm, true)) {
            return [true, ''];
        }
        return [false, 'invalid_origin'];
    }

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

    // ── Fingerprint extraction ───────────────────────────────────────────────

    /**
     * Extract the 40-char uppercase fingerprint from an ASCII-armored public key.
     * Returns empty string on failure.
     */
    public function fingerprintFromArmor(string $armor): string {
        if (extension_loaded('gnupg')) {
            return $this->fingerprintViaExtension($armor);
        }
        return $this->fingerprintViaGpgBin($armor);
    }

    private function fingerprintViaExtension(string $armor): string {
        $gpg = new \gnupg();
        $gpg->seterrormode(\gnupg::ERROR_SILENT);
        $info = $gpg->import($armor);
        return strtoupper($info['fingerprint'] ?? '');
    }

    private function fingerprintViaGpgBin(string $armor): string {
        $gpgBin = $this->findGpgBin();
        if ($gpgBin === null) {
            return '';
        }
        $home = sys_get_temp_dir() . '/capauth_gpg_' . uniqid();
        @mkdir($home, 0700, true);
        try {
            $keyFile = $home . '/key.asc';
            file_put_contents($keyFile, $armor);
            $cmd    = [$gpgBin, '--homedir', $home, '--batch', '--with-colons', '--import-options', 'show-only', '--import', $keyFile];
            $output = $this->runProcess($cmd);
            foreach (explode("\n", $output) as $line) {
                $parts = explode(':', $line);
                if (isset($parts[0], $parts[9]) && in_array($parts[0], ['pub', 'fpr'], true)) {
                    $fp = strtoupper(trim($parts[9]));
                    if (strlen($fp) === 40 || strlen($fp) === 64) {
                        return $fp;
                    }
                }
            }
        } finally {
            $this->rmrfTmp($home);
        }
        return '';
    }

    // ── Signature verification ───────────────────────────────────────────────

    /**
     * Verify that $sigArmor is a valid detached/clear-text PGP signature over
     * $data made by the key in $publicKeyArmor.
     */
    public function verifySignature(string $data, string $sigArmor, string $publicKeyArmor): bool {
        if (trim($sigArmor) === '' || trim($publicKeyArmor) === '') {
            return false;
        }
        if (extension_loaded('gnupg')) {
            return $this->verifyViaExtension($data, $sigArmor, $publicKeyArmor);
        }
        return $this->verifyViaGpgBin($data, $sigArmor, $publicKeyArmor);
    }

    private function verifyViaExtension(string $data, string $sigArmor, string $publicKeyArmor): bool {
        $home = sys_get_temp_dir() . '/capauth_gnupg_' . uniqid();
        @mkdir($home, 0700, true);
        try {
            $gpg = new \gnupg();
            $gpg->seterrormode(\gnupg::ERROR_SILENT);
            $gpg->import($publicKeyArmor);

            // If sigArmor is a clear-signed message, verify the whole thing.
            if (str_contains($sigArmor, '-----BEGIN PGP SIGNED MESSAGE-----')) {
                $result = $gpg->verify($sigArmor, false, $data);
            } else {
                $result = $gpg->verify($data, $sigArmor);
            }
            return is_array($result) && count($result) > 0 && ($result[0]['summary'] & 0x01) === 0;
        } finally {
            $this->rmrfTmp($home);
        }
    }

    private function verifyViaGpgBin(string $data, string $sigArmor, string $publicKeyArmor): bool {
        $gpgBin = $this->findGpgBin();
        if ($gpgBin === null) {
            $this->logger->warning('CapAuth: gpg binary not found; signature verification skipped.');
            return false;
        }
        $home = sys_get_temp_dir() . '/capauth_gpg_' . uniqid();
        @mkdir($home, 0700, true);
        try {
            $keyFile  = $home . '/key.asc';
            $dataFile = $home . '/data.txt';
            $sigFile  = $home . '/sig.asc';
            file_put_contents($keyFile, $publicKeyArmor);
            file_put_contents($dataFile, $data);

            // Import key.
            $this->runProcess([$gpgBin, '--homedir', $home, '--batch', '--import', $keyFile]);

            // For clear-signed messages, verify the armored blob directly.
            if (str_contains($sigArmor, '-----BEGIN PGP SIGNED MESSAGE-----')) {
                file_put_contents($sigFile, $sigArmor);
                $output = $this->runProcess(
                    [$gpgBin, '--homedir', $home, '--batch', '--verify', $sigFile],
                    $exitCode,
                );
            } else {
                file_put_contents($sigFile, $sigArmor);
                $output = $this->runProcess(
                    [$gpgBin, '--homedir', $home, '--batch', '--verify', $sigFile, $dataFile],
                    $exitCode,
                );
            }
            return $exitCode === 0;
        } catch (\Throwable $e) {
            $this->logger->error('CapAuth signature verification error: ' . $e->getMessage());
            return false;
        } finally {
            $this->rmrfTmp($home);
        }
    }

    // ── Full auth response verification ─────────────────────────────────────

    /**
     * Verify a complete CapAuth authentication response.
     *
     * Origin-binding (Tier A): the canonical payload is rebuilt from the stored
     * challenge record. If that record carries a non-empty `origin` the V2
     * (origin-bound) payload is rebuilt and the signed origin is asserted to
     * equal one of $allowedOrigins (else `invalid_origin`). A record with no
     * `origin` rebuilds the legacy V1 payload and is accepted unless
     * $requireOriginBinding is true (then `v1_rejected`).
     *
     * @param string[] $allowedOrigins        RP-configured allowed origins.
     * @param bool     $requireOriginBinding   Reject V1 challenges when true.
     * @return array{0:bool, 1:string}  [success, error_code]
     */
    public function verifyAuthResponse(
        string $fingerprint,
        string $nonceId,
        string $nonceSigArmor,
        array  $claims,
        string $claimsSigArmor,
        string $publicKeyArmor,
        array  $challengeCtx,
        array  $allowedOrigins = [],
        bool   $requireOriginBinding = false,
    ): array {
        if (trim($nonceSigArmor) === '') {
            return [false, 'invalid_nonce_signature'];
        }

        // Dispatch V1 vs V2 on the stored origin (server-asserted at issuance).
        $issuedOrigin = isset($challengeCtx['origin']) && $challengeCtx['origin'] !== ''
            ? (string) $challengeCtx['origin']
            : null;

        // Origin assertion BEFORE the signature is meaningful — and the
        // signature also covers `origin`, so tampering invalidates it anyway.
        [$originOk, $originErr] = $this->checkOrigin($issuedOrigin, $allowedOrigins, $requireOriginBinding);
        if (!$originOk) {
            return [false, $originErr];
        }

        $noncePayload = $this->canonicalNoncePayload(
            $challengeCtx['nonce'],
            $challengeCtx['client_nonce_echo'],
            $challengeCtx['issued_at'],
            $challengeCtx['service'],
            $challengeCtx['expires_at'],
            $issuedOrigin,
        );

        if (!$this->verifySignature($noncePayload, $nonceSigArmor, $publicKeyArmor)) {
            return [false, 'invalid_nonce_signature'];
        }

        // If claims are present they must also be signed.
        if (!empty($claims)) {
            if (trim($claimsSigArmor) === '') {
                return [false, 'invalid_claims_signature'];
            }
            $claimsPayload = $this->canonicalClaimsPayload($fingerprint, $nonceId, $claims);
            if (!$this->verifySignature($claimsPayload, $claimsSigArmor, $publicKeyArmor)) {
                return [false, 'invalid_claims_signature'];
            }
        }

        return [true, ''];
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** Extract the PGP signature block from a clear-signed message. */
    private function extractSigFromSignedMessage(string $msg): ?string {
        if (!preg_match(
            '/-----BEGIN PGP SIGNATURE-----.+?-----END PGP SIGNATURE-----/s',
            $msg,
            $m,
        )) {
            return null;
        }
        return $m[0];
    }

    private function findGpgBin(): ?string {
        foreach (['gpg2', 'gpg'] as $bin) {
            $path = trim((string) shell_exec("command -v {$bin} 2>/dev/null"));
            if ($path !== '') {
                return $path;
            }
        }
        return null;
    }

    private function runProcess(array $cmd, ?int &$exitCode = null): string {
        $proc = proc_open(
            $cmd,
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        if (!is_resource($proc)) {
            $exitCode = 1;
            return '';
        }
        $stdout   = stream_get_contents($pipes[1]);
        $stderr   = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($proc);
        return (string) $stdout;
    }

    private function rmrfTmp(string $dir): void {
        if (!is_dir($dir)) {
            return;
        }
        foreach (new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        ) as $item) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }
        rmdir($dir);
    }
}
