<?php

declare(strict_types=1);

namespace OCA\CapAuth\AlternativeLogin;

use OCP\Authentication\IAlternativeLogin;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\Util;

/**
 * Adds a "Sign in with CapAuth" button to the Nextcloud login page.
 *
 * Registered via IRegistrationContext::registerAlternativeLoginProvider()
 * (NC ≥ 20 for the interface; the registration call exists on the bootstrap
 * context). Clicking the button takes the user to the CapAuth challenge page,
 * which drives the PGP challenge/response and, on success, establishes the
 * session that {@see \OCA\CapAuth\User\Backend} bridges into a real login.
 */
class CapAuthLogin implements IAlternativeLogin {

    public function __construct(
        private readonly IL10N         $l10n,
        private readonly IURLGenerator $urlGenerator,
    ) {}

    /** Button label shown on the login page. */
    public function getLabel(): string {
        return $this->l10n->t('Sign in with CapAuth');
    }

    /** Target of the button — the CapAuth challenge / login page. */
    public function getLink(): string {
        return $this->urlGenerator->linkToRoute('capauth.login.showLogin');
    }

    /** CSS class applied to the button (styled in css/login.css). */
    public function getClass(): string {
        return 'capauth-login';
    }

    /**
     * Called when the login page renders — load our button styling.
     */
    public function load(): void {
        Util::addStyle('capauth', 'login');
    }
}
