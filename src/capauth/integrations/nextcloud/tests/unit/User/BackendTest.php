<?php

declare(strict_types=1);

namespace OCA\CapAuth\Tests\Unit\User;

use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\User\Backend;
use OCP\IConfig;
use OCP\ISession;
use OCP\IURLGenerator;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class BackendTest extends TestCase {
    private Backend $backend;
    private KeyRegistry $keyRegistry;
    private ISession $session;
    private IURLGenerator $urlGenerator;
    private IConfig $config;
    private LoggerInterface $logger;

    private const FP = '1234567890ABCDEF1234567890ABCDEF12345678';

    protected function setUp(): void {
        $this->keyRegistry  = $this->createMock(KeyRegistry::class);
        $this->session      = $this->createMock(ISession::class);
        $this->urlGenerator = $this->createMock(IURLGenerator::class);
        $this->config       = $this->createMock(IConfig::class);
        $this->logger       = $this->createMock(LoggerInterface::class);

        $this->backend = new Backend(
            $this->keyRegistry,
            $this->session,
            $this->urlGenerator,
            $this->config,
            $this->logger,
        );
    }

    public function testBackendName(): void {
        $this->assertSame('CapAuth', $this->backend->getBackendName());
    }

    // ── isSessionActive() / getCurrentUserId() ───────────────────────────────

    public function testSessionInactiveWhenNoFingerprint(): void {
        $this->session->method('get')->willReturn(null);
        $this->assertFalse($this->backend->isSessionActive());
        $this->assertSame('', $this->backend->getCurrentUserId());
    }

    public function testSessionInactiveWhenFingerprintNotApproved(): void {
        $this->session->method('get')->willReturnCallback(fn($k) => match ($k) {
            Backend::SESSION_FINGERPRINT => self::FP,
            default => null,
        });
        $this->keyRegistry->method('isApproved')->willReturn(false);
        $this->assertFalse($this->backend->isSessionActive());
    }

    public function testSessionActiveResolvesUid(): void {
        $this->session->method('get')->willReturnCallback(fn($k) => match ($k) {
            Backend::SESSION_FINGERPRINT => self::FP,
            default => null,
        });
        $this->keyRegistry->method('isApproved')->willReturn(true);
        $this->keyRegistry->method('getUid')->willReturn('ca_abc123');

        $this->assertTrue($this->backend->isSessionActive());
        $this->assertSame('ca_abc123', $this->backend->getCurrentUserId());
    }

    public function testSessionActiveUsesCachedUid(): void {
        $this->session->method('get')->willReturnCallback(fn($k) => match ($k) {
            Backend::SESSION_FINGERPRINT => self::FP,
            Backend::SESSION_UID         => 'ca_cached',
            default => null,
        });
        // isApproved/getUid must NOT be needed when the UID is cached.
        $this->keyRegistry->expects($this->never())->method('isApproved');
        $this->assertSame('ca_cached', $this->backend->getCurrentUserId());
    }

    // ── logout() clears session markers ──────────────────────────────────────

    public function testLogoutClearsSession(): void {
        $removed = [];
        $this->session->method('remove')->willReturnCallback(function ($k) use (&$removed) {
            $removed[] = $k;
        });
        $this->backend->logout();
        $this->assertContains(Backend::SESSION_FINGERPRINT, $removed);
        $this->assertContains(Backend::SESSION_UID, $removed);
    }

    // ── user listing ─────────────────────────────────────────────────────────

    public function testCountUsers(): void {
        $this->keyRegistry->method('listUids')->willReturn(['a', 'b', 'c']);
        $this->assertSame(3, $this->backend->countUsers());
    }

    public function testGetUsersFiltersBySearch(): void {
        $this->keyRegistry->method('listUids')->willReturn(['alice', 'bob', 'alan']);
        $this->assertSame(['alice', 'alan'], array_values($this->backend->getUsers('al')));
    }

    public function testUserExistsDelegatesToRegistry(): void {
        $this->keyRegistry->method('uidHasKey')->with('ca_x')->willReturn(true);
        $this->assertTrue($this->backend->userExists('ca_x'));
        $this->assertFalse($this->backend->userExists(''));
    }

    public function testGetDisplayNameFallsBackToUid(): void {
        $this->assertSame('ca_x', $this->backend->getDisplayName('ca_x'));
    }

    public function testImplementsNoPasswordActions(): void {
        $this->assertFalse($this->backend->implementsActions(0xFFFF));
    }
}
