<?php
/**
 * CapAuth passwordless login page.
 *
 * Rendered by LoginController::showLogin() with the guest layout. Driven by
 * js/login.js (full-page flow: #capauth-step-fingerprint → #capauth-step-challenge).
 *
 * @var array $_ template parameters
 * @var \OCP\IL10N $l
 */

/** @var \OCP\Util $util */
\OCP\Util::addScript('capauth', 'login');
\OCP\Util::addStyle('capauth', 'login');

$redirectUrl = $_['redirect_url'] ?? '';
?>
<div id="capauth-login" class="capauth-login-wrap">
    <h2><?php p($l->t('Sign in with CapAuth')); ?></h2>
    <p class="capauth-subtitle">
        <?php p($l->t('Authenticate with your sovereign PGP key — no password required.')); ?>
    </p>

    <!-- Step 1: fingerprint -->
    <div id="capauth-step-fingerprint" class="capauth-step">
        <label for="capauth-fingerprint-input"><?php p($l->t('PGP key fingerprint')); ?></label>
        <input type="text"
               id="capauth-fingerprint-input"
               autocomplete="off"
               spellcheck="false"
               maxlength="40"
               placeholder="<?php p($l->t('40-character hex fingerprint')); ?>" />
        <button id="capauth-fingerprint-btn" class="primary">
            <?php p($l->t('Request challenge')); ?>
        </button>
        <div id="capauth-fp-error" class="capauth-error" style="display:none"></div>
    </div>

    <!-- Step 2: challenge / signature -->
    <div id="capauth-step-challenge" class="capauth-step" style="display:none">
        <p><?php p($l->t('Sign the following challenge with your CapAuth key:')); ?></p>
        <pre id="capauth-nonce-display" class="capauth-challenge"></pre>
        <button id="capauth-copy-btn" type="button"><?php p($l->t('Copy')); ?></button>

        <div id="capauth-extension-notice" style="display:none" class="capauth-notice">
            <?php p($l->t('CapAuth browser extension detected — signing automatically…')); ?>
        </div>

        <label for="capauth-sig-input"><?php p($l->t('Paste your PGP signature')); ?></label>
        <textarea id="capauth-sig-input" rows="8"
                  placeholder="-----BEGIN PGP SIGNATURE-----"></textarea>
        <button id="capauth-verify-btn" class="primary"><?php p($l->t('Sign in')); ?></button>
        <span id="capauth-spinner" class="icon-loading-small" style="display:none"></span>
        <div id="capauth-verify-error" class="capauth-error" style="display:none"></div>
    </div>

    <input type="hidden" id="capauth-redirect-url" value="<?php p($redirectUrl); ?>" />
</div>
