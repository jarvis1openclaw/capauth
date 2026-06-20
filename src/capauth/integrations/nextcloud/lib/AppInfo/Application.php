<?php

declare(strict_types=1);

namespace OCA\CapAuth\AppInfo;

use OCA\CapAuth\AlternativeLogin\CapAuthLogin;
use OCA\CapAuth\Middleware\PgpVerificationMiddleware;
use OCA\CapAuth\User\Backend as CapAuthBackend;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\IConfig;
use OCP\IUserManager;

/**
 * CapAuth Nextcloud application bootstrap.
 *
 * As of 0.3.0 CapAuth is a PASSWORDLESS PRIMARY authentication backend (no
 * longer a second factor). Two pieces make that work:
 *
 *   - {@see CapAuthBackend} — an IApacheBackend user backend that bridges a
 *     PGP-verified session into a real Nextcloud login.
 *   - {@see CapAuthLogin}   — the "Sign in with CapAuth" alternative-login
 *     button on the login page.
 *
 * The Bearer-token middleware is retained for API/app token auth.
 *
 * Modelled on nextcloud/user_oidc's AppInfo\Application: the user backend is
 * registered in boot() (where the container can resolve it) with a version
 * gate (IUserManager::registerBackend on NC ≥ 32, else \OC_User::useBackend),
 * and the alternative-login provider is registered in register() (NC ≥ 34).
 */
class Application extends App implements IBootstrap {
    public const APP_ID = 'capauth';

    public function __construct() {
        parent::__construct(self::APP_ID);
    }

    public function register(IRegistrationContext $context): void {
        // Bearer-token auth on every controller request (API access).
        $context->registerMiddleware(PgpVerificationMiddleware::class);

        // Add the "Sign in with CapAuth" button to the login page.
        // registerAlternativeLoginProvider() is available on the bootstrap
        // registration context (the documented path is NC ≥ 34; the call is
        // also present earlier, so guard on method_exists for portability).
        if (method_exists($context, 'registerAlternativeLoginProvider')) {
            $context->registerAlternativeLoginProvider(CapAuthLogin::class);
        }
    }

    public function boot(IBootContext $context): void {
        $context->injectFn(function (
            IUserManager $userManager,
            IConfig $config,
            CapAuthBackend $backend,
        ): void {
            // Register the passwordless user backend.
            // NC ≥ 32: IUserManager::registerBackend(); else legacy OC_User.
            $version = $config->getSystemValueString('version', '0.0.0');
            if (
                version_compare($version, '32.0.0', '>=')
                && method_exists($userManager, 'registerBackend')
            ) {
                $userManager->registerBackend($backend);
            } else {
                \OC_User::useBackend($backend);
            }
        });
    }
}
