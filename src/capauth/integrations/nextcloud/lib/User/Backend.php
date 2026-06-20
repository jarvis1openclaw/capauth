<?php

declare(strict_types=1);

namespace OCA\CapAuth\User;

use OCA\CapAuth\Db\KeyRegistry;
use OCP\Authentication\IApacheBackend;
use OCP\IConfig;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\User\Backend\ABackend;
use OCP\User\Backend\ICountUsersBackend;
use OCP\User\Backend\ICustomLogout;
use OCP\User\Backend\IGetDisplayNameBackend;
use Psr\Log\LoggerInterface;

/**
 * CapAuth passwordless primary user backend.
 *
 * This is the heart of the passwordless refactor. Instead of acting as a
 * Nextcloud second factor (which is impossible to make primary — 2FA always
 * runs *after* a password login), CapAuth bridges an out-of-band-established
 * PGP session into a real Nextcloud login via {@see IApacheBackend}.
 *
 * The flow (mirrors how user_oidc / user_saml work):
 *   1. The browser completes the PGP challenge/response against
 *      {@see \OCA\CapAuth\Controller\LoginController}. On success the verified
 *      fingerprint is written into the PHP session under SESSION_FINGERPRINT.
 *   2. Nextcloud's auth stack, on the next request, calls IApacheBackend on
 *      every registered backend. isSessionActive() reports "yes, a CapAuth
 *      session exists" and getCurrentUserId() returns the mapped UID.
 *   3. Nextcloud logs that UID in — no password, no second factor.
 *
 * The fingerprint→UID mapping is the source of truth in {@see KeyRegistry}
 * (column `uid`). Local password admins keep working because this backend
 * only claims a session when SESSION_FINGERPRINT is set; when it is absent
 * isSessionActive() returns false and Nextcloud falls through to the normal
 * (Database) backend.
 */
class Backend extends ABackend implements
    IApacheBackend,
    IGetDisplayNameBackend,
    ICountUsersBackend,
    ICustomLogout {

    /** Session key holding the verified PGP fingerprint after challenge/response. */
    public const SESSION_FINGERPRINT = 'capauth.verified_fingerprint';

    /** Session key holding the resolved Nextcloud UID (cache to avoid re-lookups). */
    public const SESSION_UID = 'capauth.verified_uid';

    public function __construct(
        private readonly KeyRegistry      $keyRegistry,
        private readonly ISession         $session,
        private readonly IURLGenerator    $urlGenerator,
        private readonly IConfig          $config,
        private readonly LoggerInterface  $logger,
    ) {}

    // ── Backend identity ─────────────────────────────────────────────────────

    public function getBackendName(): string {
        return 'CapAuth';
    }

    // ── IApacheBackend ───────────────────────────────────────────────────────
    //
    // These three methods are what make a passwordless login possible. They are
    // polled by Nextcloud's \OC\User\Session on each request; a non-empty
    // getCurrentUserId() while isSessionActive() is true logs the user in.

    /**
     * True when this request carries a verified CapAuth PGP session.
     *
     * Returns false (so the normal password backend takes over) when no
     * fingerprint has been verified — this is what keeps local admin login
     * working alongside CapAuth.
     */
    public function isSessionActive(): bool {
        $fp = $this->session->get(self::SESSION_FINGERPRINT);
        if (!is_string($fp) || $fp === '') {
            return false;
        }
        // Only claim the session if the fingerprint resolves to a known,
        // approved UID. A dangling fingerprint must not block password login.
        return $this->resolveUid($fp) !== null;
    }

    /**
     * The UID for the verified fingerprint in the current session, or '' when
     * there is no active CapAuth session.
     */
    public function getCurrentUserId(): string {
        $fp = $this->session->get(self::SESSION_FINGERPRINT);
        if (!is_string($fp) || $fp === '') {
            return '';
        }
        $uid = $this->resolveUid($fp);
        return $uid ?? '';
    }

    public function getLogoutUrl(): string {
        // Send the user back to the standard logout, then to the CapAuth login.
        return $this->urlGenerator->linkToRouteAbsolute('core.login.showLoginForm');
    }

    // ── ICustomLogout ────────────────────────────────────────────────────────

    /**
     * Clear the CapAuth session markers on logout so the next visit starts a
     * fresh challenge instead of silently re-logging the user in.
     */
    public function logout(): void {
        $this->session->remove(self::SESSION_FINGERPRINT);
        $this->session->remove(self::SESSION_UID);
    }

    // ── User existence / enumeration ─────────────────────────────────────────

    public function userExists($uid): bool {
        if (!is_string($uid) || $uid === '') {
            return false;
        }
        return $this->keyRegistry->uidHasKey($uid);
    }

    /**
     * @param string $search
     * @param null|int $limit
     * @param null|int $offset
     * @return string[] an array of all uids
     */
    public function getUsers($search = '', $limit = null, $offset = null): array {
        $uids = $this->keyRegistry->listUids();
        if ($search !== '') {
            $needle = mb_strtolower($search);
            $uids = array_values(array_filter(
                $uids,
                static fn(string $u): bool => str_contains(mb_strtolower($u), $needle),
            ));
        }
        if ($offset !== null) {
            $uids = array_slice($uids, (int) $offset);
        }
        if ($limit !== null) {
            $uids = array_slice($uids, 0, (int) $limit);
        }
        return $uids;
    }

    // ── IGetDisplayNameBackend ───────────────────────────────────────────────

    public function getDisplayName($uid): string {
        // The display name proper lives on the IUser (set by
        // UserProvisioningService from claims). The backend just needs to
        // return *something* stable; the UID is a safe fallback.
        return (string) $uid;
    }

    /**
     * @param string $search
     * @param null|int $limit
     * @param null|int $offset
     * @return array<string,string> [uid => displayName]
     */
    public function getDisplayNames($search = '', $limit = null, $offset = null): array {
        $out = [];
        foreach ($this->getUsers($search, $limit, $offset) as $uid) {
            $out[$uid] = $this->getDisplayName($uid);
        }
        return $out;
    }

    // ── ICountUsersBackend ───────────────────────────────────────────────────

    /**
     * @return int|false the number of users on success, false on failure
     */
    public function countUsers() {
        return count($this->keyRegistry->listUids());
    }

    // ── Capability flags ─────────────────────────────────────────────────────

    /**
     * CapAuth has no password concept; report no implemented password actions
     * so Nextcloud never offers "change password" for these users.
     */
    public function implementsActions($actions): bool {
        return false;
    }

    public function hasUserListings(): bool {
        return true;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Resolve a verified fingerprint to a Nextcloud UID, requiring the key to
     * be approved. Caches the result in the session to avoid a DB hit per
     * request. Returns null when no approved key maps to the fingerprint.
     */
    private function resolveUid(string $fingerprint): ?string {
        $fp = strtoupper(trim($fingerprint));

        $cached = $this->session->get(self::SESSION_UID);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        if (!$this->keyRegistry->isApproved($fp)) {
            $this->logger->debug('CapAuth backend: fingerprint not approved', ['fp' => $fp]);
            return null;
        }

        $uid = $this->keyRegistry->getUid($fp);
        if ($uid === null || $uid === '') {
            return null;
        }

        $this->session->set(self::SESSION_UID, $uid);
        return $uid;
    }
}
