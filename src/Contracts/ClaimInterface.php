<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Contracts;

interface ClaimInterface
{
    /**
     * Set the claim value, and call a validate method.
     *
     * @param mixed $value
     *
     * @throws \HyperfExt\Jwt\Exceptions\InvalidClaimException
     *
     * @return $this
     */
    public function setValue($value);

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue();

    /**
     * Set the claim name.
     *
     * @return $this
     */
    public function setName(string $name);

    /**
     * Get the claim name.
     */
    public function getName(): string;

    /**
     * Validate the Claim value.
     */
    public function validate(bool $ignoreExpired = false): bool;
}
