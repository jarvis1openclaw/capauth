<?php

declare(strict_types=1);

namespace OCA\CapAuth\Controller;

use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\Service\ChallengeService;
use OCA\CapAuth\Service\UserProvisioningService;
use OCA\CapAuth\Service\VerifierService;
use OCA\CapAuth\User\Backend as CapAuthBackend;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserManager;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

/**
 * HTTP endpoints for the CapAuth passwordless PRIMARY login flow.
 *
 * Routes (defined in appinfo/routes.php):
 *   GET  /apps/capauth/login                 → showLogin()   (the login page)
 *   POST /apps/capauth/v1/challenge          → challenge()   (issue nonce)
 *   GET  /apps/capauth/v1/nonce/{nonce}/status → nonceStatus()
 *   POST /apps/capauth/v1/verify             → verify()      (PGP verify + login)
 *
 * Unlike the old 2FA provider (which could only run as a *second* factor after
 * a password), this controller drives a full primary login: on successful
 * verification it writes the verified fingerprint into the PHP session so that
 * {@see CapAuthBackend} (an IApacheBackend) can bridge it into a real
 * Nextcloud login on the same request, then completes the user session.
 */
class LoginController extends Controller {
    public function __construct(
        string                            $appName,
        IRequest                          $request,
        private readonly ChallengeService         $challengeService,
        private readonly VerifierService          $verifierService,
        private readonly KeyRegistry              $keyRegistry,
        private readonly UserProvisioningService  $provisioningService,
        private readonly ISession                 $session,
        private readonly IUserSession             $userSession,
        private readonly IUserManager             $userManager,
        private readonly IConfig                  $config,
        private readonly LoggerInterface          $logger,
    ) {
        parent::__construct($appName, $request);
    }

    // ── Login page ───────────────────────────────────────────────────────────

    /**
     * GET /apps/capauth/login
     *
     * Renders the standalone CapAuth login page (the target of the
     * "Sign in with CapAuth" alternative-login button). Rendered with the
     * 'guest' layout so it works for not-yet-authenticated users.
     *
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function showLogin(string $redirect_url = ''): TemplateResponse {
        $this->session->set('capauth.redirect_url', $redirect_url);
        return new TemplateResponse(
            'capauth',
            'login',
            ['redirect_url' => $redirect_url],
            TemplateResponse::RENDER_AS_GUEST,
        );
    }

    // ── Challenge issuance ───────────────────────────────────────────────────

    /**
     * POST /apps/capauth/v1/challenge
     * Body: { "fingerprint": "...", "client_nonce": "..." }
     *
     * Returns the challenge context the client must sign.
     *
     * @NoCSRFRequired
     * @PublicPage
     * @UseSession
     */
    public function challenge(): JSONResponse {
        $body        = $this->parseJsonBody();
        $fingerprint = trim($body['fingerprint'] ?? '');
        $clientNonce = $body['client_nonce'] ?? '';

        if (!$this->isValidFingerprint($fingerprint)) {
            return new JSONResponse(
                ['error' => 'invalid_fingerprint'],
                Http::STATUS_BAD_REQUEST,
            );
        }

        $service   = $this->config->getAppValue(
            'capauth',
            'service_name',
            $this->request->getServerHost(),
        );
        // Origin-binding (Tier A): the server ASSERTS its own canonical RP
        // origin into the challenge so the client signs over it (V2). On verify
        // we confirm the signed origin matches an allowed origin.
        $origin    = $this->rpOrigin();
        $challenge = $this->challengeService->issue($fingerprint, $service, $clientNonce, $origin);

        // Store fingerprint + challenge in the server-side session for the
        // subsequent verify() call.
        $this->session->set('capauth.fingerprint', strtoupper($fingerprint));
        $this->session->set('capauth.challenge', $challenge);

        return new JSONResponse($challenge);
    }

    // ── Nonce status polling ─────────────────────────────────────────────────

    /**
     * GET /apps/capauth/v1/nonce/{nonce}/status
     *
     * Returns: { "status": "pending"|"consumed"|"expired"|"unknown" }
     *
     * @NoCSRFRequired
     * @PublicPage
     */
    public function nonceStatus(string $nonce): JSONResponse {
        $rec = $this->challengeService->peek($nonce);
        if ($rec === null) {
            return new JSONResponse(['status' => 'unknown']);
        }
        if ($rec['used']) {
            return new JSONResponse(['status' => 'consumed']);
        }
        if (new \DateTimeImmutable() > new \DateTimeImmutable($rec['expires_at'])) {
            return new JSONResponse(['status' => 'expired']);
        }
        return new JSONResponse(['status' => 'pending']);
    }

    // ── Verification + primary login ─────────────────────────────────────────

    /**
     * POST /apps/capauth/v1/verify
     * Body: {
     *   "fingerprint":      "...",
     *   "nonce":            "...",
     *   "nonce_signature":  "...",
     *   "claims":           { ... },    // optional
     *   "claims_signature": "...",      // required when claims present
     *   "public_key":       "..."       // optional, used for first-time provisioning
     * }
     *
     * On success this performs a PASSWORDLESS PRIMARY login:
     *   1. Verifies the PGP signature(s) against the approved key.
     *   2. Provisions / resolves the Nextcloud user from the claims.
     *   3. Writes the verified fingerprint into the session so CapAuthBackend
     *      (IApacheBackend) recognises it.
     *   4. Calls IUserSession::completeLogin() + createSessionToken() to
     *      establish a real, fully-authenticated Nextcloud session.
     *
     * @NoCSRFRequired
     * @PublicPage
     * @UseSession
     */
    public function verify(): JSONResponse {
        $body        = $this->parseJsonBody();
        $fingerprint = strtoupper(trim($body['fingerprint'] ?? ''));
        $nonceId     = $body['nonce']            ?? '';
        $nonceSig    = $body['nonce_signature']  ?? '';
        $claims      = $body['claims']           ?? [];
        $claimsSig   = $body['claims_signature'] ?? '';
        $publicKey   = $body['public_key']       ?? '';

        if (!$this->isValidFingerprint($fingerprint) || $nonceId === '' || $nonceSig === '') {
            return new JSONResponse(['error' => 'bad_request'], Http::STATUS_BAD_REQUEST);
        }

        // Consume nonce (prevents replay). The consumed record IS the
        // authoritative challenge context — rebuild the canonical payload from
        // it, NOT from the PHP session (which doesn't reliably persist across
        // the pre-login challenge→verify request pair).
        [$nonceOk, $nonceErr, $challengeCtx] = $this->challengeService->consume($nonceId, $fingerprint);
        if (!$nonceOk) {
            return new JSONResponse(['error' => $nonceErr], Http::STATUS_UNAUTHORIZED);
        }
        if (!is_array($challengeCtx)) {
            return new JSONResponse(['error' => 'no_challenge'], Http::STATUS_UNAUTHORIZED);
        }

        // Key must be approved (enrollment-approval gate).
        if (!$this->keyRegistry->isApproved($fingerprint)) {
            return new JSONResponse(['error' => 'key_not_approved'], Http::STATUS_FORBIDDEN);
        }
        $publicKeyArmor = $this->keyRegistry->getPublicKey($fingerprint);
        if ($publicKeyArmor === null) {
            return new JSONResponse(['error' => 'key_not_found'], Http::STATUS_NOT_FOUND);
        }

        // PGP verification + Tier-A origin assertion. The allowed origins
        // default to the RP's own scheme+host (reverse-proxy aware); the
        // dual-accept window is controlled by capauth.require_origin_binding.
        [$ok, $err] = $this->verifierService->verifyAuthResponse(
            fingerprint:          $fingerprint,
            nonceId:              $nonceId,
            nonceSigArmor:        $nonceSig,
            claims:               is_array($claims) ? $claims : [],
            claimsSigArmor:       $claimsSig,
            publicKeyArmor:       $publicKeyArmor,
            challengeCtx:         $challengeCtx,
            allowedOrigins:       $this->allowedOrigins(),
            requireOriginBinding: $this->requireOriginBinding(),
        );

        if (!$ok) {
            return new JSONResponse(['error' => $err], Http::STATUS_UNAUTHORIZED);
        }

        // Provision / resolve the Nextcloud user from the verified identity.
        $provisionClaims = is_array($claims) ? $claims : [];
        if ($publicKey !== '' && !isset($provisionClaims['public_key'])) {
            $provisionClaims['public_key'] = $publicKey;
        }
        $user = $this->provisioningService->provisionFromFingerprint($fingerprint, $provisionClaims);

        // Fall back to an existing registry mapping if provisioning is disabled.
        if ($user === null) {
            $uid  = $this->keyRegistry->getUid($fingerprint);
            $user = $uid !== null ? $this->userManager->get($uid) : null;
        }

        if ($user === null) {
            return new JSONResponse(['error' => 'user_not_found'], Http::STATUS_NOT_FOUND);
        }

        $this->keyRegistry->recordAuth($fingerprint);

        // ── Establish the passwordless primary session ──────────────────────
        // 1. Mark the fingerprint verified so CapAuthBackend (IApacheBackend)
        //    will claim this session and report the UID.
        $this->session->set(CapAuthBackend::SESSION_FINGERPRINT, $fingerprint);
        $this->session->set(CapAuthBackend::SESSION_UID, $user->getUID());

        // 2. Complete the login through the user session so Nextcloud runs its
        //    normal post-login hooks, then create a session token so the
        //    browser stays authenticated on subsequent requests.
        try {
            if (method_exists($this->userSession, 'completeLogin')) {
                // NB: 'password' must be a STRING ('' for passwordless) — NC's
                // PostLoginEvent constructor types it as string and rejects null.
                $this->userSession->completeLogin($user, [
                    'loginName' => $user->getUID(),
                    'password'  => '',
                ]);
            } else {
                $this->userSession->setUser($user);
            }

            if (method_exists($this->userSession, 'createSessionToken')) {
                // Last arg (password) must be a string too, not null.
                $this->userSession->createSessionToken(
                    $this->request,
                    $user->getUID(),
                    $user->getUID(),
                    '',
                );
            }
        } catch (\Throwable $e) {
            $this->logger->error('CapAuth: failed to complete passwordless login: ' . $e->getMessage());
            // Last-resort: at least set the user on the session.
            $this->userSession->setUser($user);
        }

        $redirect = $this->session->get('capauth.redirect_url');
        return new JSONResponse([
            'status'       => 'ok',
            'uid'          => $user->getUID(),
            'redirect_url' => is_string($redirect) && $redirect !== '' ? $redirect : '/',
        ]);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    // ── Origin-binding helpers (Tier A) ──────────────────────────────────────

    /**
     * Compute this RP's canonical origin (scheme://host[:port]).
     *
     * Reverse-proxy aware: Nextcloud's `overwriteprotocol` / `overwritehost`
     * config (set when behind a proxy) take precedence over the raw request
     * values so the asserted origin matches the public-facing URL the browser
     * actually used. Falls back to the request's own scheme + host.
     */
    private function rpOrigin(): string {
        $proto = $this->config->getSystemValue('overwriteprotocol', '');
        if (!is_string($proto) || $proto === '') {
            $proto = $this->request->getServerProtocol() ?: 'https';
        }

        $host = $this->config->getSystemValue('overwritehost', '');
        if (!is_string($host) || $host === '') {
            $host = $this->request->getServerHost();
        }

        return strtolower($proto) . '://' . $host;
    }

    /**
     * The RP-configured allowed origins for the V2 origin check.
     *
     * Config key `capauth.allowed_origins` (comma/whitespace separated). When
     * unset it defaults to this RP's own origin ({@see rpOrigin()}).
     *
     * @return string[]
     */
    private function allowedOrigins(): array {
        $raw = $this->config->getAppValue('capauth', 'allowed_origins', '');
        if (is_string($raw) && trim($raw) !== '') {
            $parts = preg_split('/[\s,]+/', trim($raw)) ?: [];
            $parts = array_values(array_filter(array_map('trim', $parts), fn($p) => $p !== ''));
            if (!empty($parts)) {
                return $parts;
            }
        }
        return [$this->rpOrigin()];
    }

    /**
     * Whether V1 (origin-less) challenges must be rejected.
     *
     * Config key `capauth.require_origin_binding` (default false → dual-accept).
     */
    private function requireOriginBinding(): bool {
        $val = $this->config->getAppValue('capauth', 'require_origin_binding', 'false');
        return filter_var($val, FILTER_VALIDATE_BOOLEAN);
    }

    private function parseJsonBody(): array {
        $raw = file_get_contents('php://input');
        if ($raw === false || $raw === '') {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    private function isValidFingerprint(string $fp): bool {
        return (bool) preg_match('/^[0-9A-Fa-f]{40}$|^[0-9A-Fa-f]{64}$/', $fp);
    }
}
