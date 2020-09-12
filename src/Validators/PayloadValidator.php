<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Validators;

use Hyperf\Contract\ConfigInterface;
use HyperfExt\Jwt\Claims\Collection;
use HyperfExt\Jwt\Contracts\PayloadValidatorInterface;
use HyperfExt\Jwt\Exceptions\JwtException;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;

class PayloadValidator implements PayloadValidatorInterface
{
    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims = [];

    public function __construct(ConfigInterface $config)
    {
        $this->setRequiredClaims($config->get('jwt.required_claims', []));
    }

    public function check(Collection $value, bool $ignoreExpired = false): Collection
    {
        $this->validateStructure($value);

        return $this->validatePayload($value, $ignoreExpired);
    }

    public function isValid(Collection $value, bool $ignoreExpired = false): bool
    {
        try {
            $this->check($value, $ignoreExpired);
        } catch (JwtException $e) {
            return false;
        }

        return true;
    }

    /**
     * Set the required claims.
     *
     * @return $this
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @throws \HyperfExt\Jwt\Exceptions\TokenInvalidException
     */
    protected function validateStructure(Collection $claims)
    {
        if ($this->requiredClaims and ! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('JWT payload does not contain the required claims');
        }
        return $this;
    }

    /**
     * Validate the payload timestamps.
     *
     * @throws \HyperfExt\Jwt\Exceptions\TokenExpiredException
     * @throws \HyperfExt\Jwt\Exceptions\TokenInvalidException
     */
    protected function validatePayload(Collection $claims, bool $ignoreExpired = false): Collection
    {
        return $claims->validate($ignoreExpired);
    }
}
