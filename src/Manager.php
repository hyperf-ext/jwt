<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt;

use Hyperf\Utils\Arr;
use HyperfExt\Jwt\Claims\Factory as ClaimFactory;
use HyperfExt\Jwt\Contracts\CodecInterface;
use HyperfExt\Jwt\Contracts\ManagerInterface;
use HyperfExt\Jwt\Exceptions\JwtException;
use HyperfExt\Jwt\Exceptions\TokenBlacklistedException;

class Manager implements ManagerInterface
{
    /**
     * The JWT codec interface.
     *
     * @var \HyperfExt\Jwt\Contracts\CodecInterface
     */
    protected $codec;

    /**
     * The blacklist interface.
     *
     * @var \HyperfExt\Jwt\Blacklist
     */
    protected $blacklist;

    /**
     * the claim factory.
     *
     * @var \HyperfExt\Jwt\Claims\Factory
     */
    protected $claimFactory;

    /**
     * the payload factory.
     *
     * @var \HyperfExt\Jwt\PayloadFactory
     */
    protected $payloadFactory;

    /**
     * The blacklist flag.
     *
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * the persistent claims.
     *
     * @var array
     */
    protected $persistentClaims = [];

    public function __construct(
        CodecInterface $codec,
        Blacklist $blacklist,
        ClaimFactory $claimFactory,
        PayloadFactory $payloadFactory
    ) {
        $this->codec = $codec;
        $this->blacklist = $blacklist;
        $this->claimFactory = $claimFactory;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     */
    public function encode(Payload $payload): Token
    {
        $token = $this->codec->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @throws \HyperfExt\Jwt\Exceptions\TokenBlacklistedException
     */
    public function decode(Token $token, bool $checkBlacklist = true, bool $ignoreExpired = false): Payload
    {
        $payload = $this->payloadFactory->make($this->codec->decode($token->get()), $ignoreExpired);

        if ($checkBlacklist and $this->blacklistEnabled and $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @throws \HyperfExt\Jwt\Exceptions\TokenBlacklistedException
     * @throws \HyperfExt\Jwt\Exceptions\JwtException
     */
    public function refresh(Token $token, bool $forceForever = false, array $customClaims = []): Token
    {
        $claims = $this->buildRefreshClaims($this->decode($token, true, true));

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token, $forceForever);
        }

        $claims = array_merge($claims, $customClaims);

        // Return the new token
        return $this->encode($this->payloadFactory->make($claims));
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @throws \HyperfExt\Jwt\Exceptions\JwtException
     */
    public function invalidate(Token $token, bool $forceForever = false): bool
    {
        if (! $this->blacklistEnabled) {
            throw new JwtException('You must have the blacklist enabled to invalidate a token.');
        }

        return call_user_func(
            [$this->blacklist, $forceForever ? 'addForever' : 'add'],
            $this->decode($token, false, true)
        );
    }

    /**
     * Get the Claim Factory instance.
     */
    public function getClaimFactory(): ClaimFactory
    {
        return $this->claimFactory;
    }

    /**
     * Get the Payload Factory instance.
     */
    public function getPayloadFactory(): PayloadFactory
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWT codec instance.
     */
    public function getCodec(): CodecInterface
    {
        return $this->codec;
    }

    /**
     * Get the Blacklist instance.
     */
    public function getBlacklist(): Blacklist
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     *
     * @return $this
     */
    public function setBlacklistEnabled(bool $enabled)
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Set the claims to be persisted when refreshing a token.
     *
     * @return $this
     */
    public function setPersistentClaims(array $claims)
    {
        $this->persistentClaims = $claims;

        return $this;
    }

    /**
     * Get the claims to be persisted when refreshing a token.
     */
    public function getPersistentClaims(): array
    {
        return $this->persistentClaims;
    }

    /**
     * Build the claims to go into the refreshed token.
     *
     * @param \HyperfExt\Jwt\Payload $payload
     *
     * @return array
     */
    protected function buildRefreshClaims(Payload $payload)
    {
        // Get the claims to be persisted from the payload
        $persistentClaims = Arr::only($payload->toArray(), $this->persistentClaims);

        // persist the relevant claims
        return array_merge(
            $persistentClaims,
            [
                'sub' => $payload['sub'],
                'iat' => $payload['iat'],
            ]
        );
    }
}
