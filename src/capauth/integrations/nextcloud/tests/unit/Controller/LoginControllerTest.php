<?php

declare(strict_types=1);

namespace OCA\CapAuth\Tests\Unit\Controller;

use OCA\CapAuth\Controller\LoginController;
use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\Service\ChallengeService;
use OCA\CapAuth\Service\UserProvisioningService;
use OCA\CapAuth\Service\VerifierService;
use OCP\AppFramework\Http;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserManager;
use OCP\IUserSession;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class LoginControllerTest extends TestCase {
    private LoginController $controller;
    private ChallengeService $challengeService;
    private VerifierService $verifierService;
    private KeyRegistry $keyRegistry;
    private UserProvisioningService $provisioningService;
    private ISession $session;
    private IUserSession $userSession;
    private IUserManager $userManager;
    private IConfig $config;
    private LoggerInterface $logger;

    protected function setUp(): void {
        $this->challengeService    = $this->createMock(ChallengeService::class);
        $this->verifierService     = $this->createMock(VerifierService::class);
        $this->keyRegistry         = $this->createMock(KeyRegistry::class);
        $this->provisioningService = $this->createMock(UserProvisioningService::class);
        $this->session             = $this->createMock(ISession::class);
        $this->userSession         = $this->createMock(IUserSession::class);
        $this->userManager         = $this->createMock(IUserManager::class);
        $this->config              = $this->createMock(IConfig::class);
        $this->logger              = $this->createMock(LoggerInterface::class);
        $request                   = $this->createMock(IRequest::class);

        $this->controller = new LoginController(
            'capauth',
            $request,
            $this->challengeService,
            $this->verifierService,
            $this->keyRegistry,
            $this->provisioningService,
            $this->session,
            $this->userSession,
            $this->userManager,
            $this->config,
            $this->logger,
        );
    }

    // ── challenge() ──────────────────────────────────────────────────────────

    public function testControllerInstantiates(): void {
        // Full HTTP round-trips (php://input bodies) are covered by the
        // integration suite. Here we just verify the controller wires up with
        // the passwordless-primary constructor signature.
        $this->assertInstanceOf(LoginController::class, $this->controller);
    }

    // ── nonceStatus() ────────────────────────────────────────────────────────

    public function testNonceStatusReturnsUnknownForMissingNonce(): void {
        $this->challengeService->method('peek')->willReturn(null);
        $resp = $this->controller->nonceStatus('nonexistent-uuid');
        $data = json_decode(json_encode($resp->getData()), true);
        $this->assertSame('unknown', $data['status']);
    }

    public function testNonceStatusReturnsPendingForValidNonce(): void {
        $future = (new \DateTimeImmutable('+1 hour'))->format(\DateTimeInterface::ATOM);
        $this->challengeService->method('peek')->willReturn([
            'expires_at' => $future,
            'used'       => false,
        ]);
        $resp = $this->controller->nonceStatus('some-uuid');
        $data = json_decode(json_encode($resp->getData()), true);
        $this->assertSame('pending', $data['status']);
    }

    public function testNonceStatusReturnsConsumedForUsedNonce(): void {
        $future = (new \DateTimeImmutable('+1 hour'))->format(\DateTimeInterface::ATOM);
        $this->challengeService->method('peek')->willReturn([
            'expires_at' => $future,
            'used'       => true,
        ]);
        $resp = $this->controller->nonceStatus('used-uuid');
        $data = json_decode(json_encode($resp->getData()), true);
        $this->assertSame('consumed', $data['status']);
    }

    public function testNonceStatusReturnsExpiredForPastNonce(): void {
        $past = (new \DateTimeImmutable('-1 hour'))->format(\DateTimeInterface::ATOM);
        $this->challengeService->method('peek')->willReturn([
            'expires_at' => $past,
            'used'       => false,
        ]);
        $resp = $this->controller->nonceStatus('old-uuid');
        $data = json_decode(json_encode($resp->getData()), true);
        $this->assertSame('expired', $data['status']);
    }
}
