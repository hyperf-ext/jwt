<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Claims;

use Hyperf\Utils\ApplicationContext;
use Hyperf\Utils\Str;
use HyperfExt\Jwt\Contracts\ClaimInterface;
use Psr\Http\Message\ServerRequestInterface;

class Factory
{
    /**
     * The TTL.
     *
     * @var null|int
     */
    protected $ttl;

    /**
     * The refresh TTL.
     *
     * @var null|int
     */
    protected $refreshTtl;

    /**
     * Time leeway in seconds.
     *
     * @var int
     */
    protected $leeway;

    /**
     * The classes map.
     *
     * @var array
     */
    private $classMap = [
        'aud' => Audience::class,
        'exp' => Expiration::class,
        'iat' => IssuedAt::class,
        'iss' => Issuer::class,
        'jti' => JwtId::class,
        'nbf' => NotBefore::class,
        'sub' => Subject::class,
    ];

    public function __construct(?int $ttl, ?int $refreshTtl, int $leeway = 0)
    {
        $this->setTtl($ttl);
        $this->setRefreshTtl($refreshTtl);
        $this->setLeeway($leeway);
    }

    /**
     * Get the instance of the claim when passing the name and value.
     *
     * @param mixed $value
     */
    public function get(string $name, $value): ClaimInterface
    {
        if ($this->has($name)) {
            $claim = make($this->classMap[$name], ['factory' => $this, 'value' => $value]);

            return method_exists($claim, 'setLeeway') ?
                $claim->setLeeway($this->leeway) :
                $claim;
        }

        return new Custom($name, $value);
    }

    /**
     * Check whether the claim exists.
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->classMap);
    }

    /**
     * Generate the initial value and return the Claim instance.
     */
    public function make(string $name): ClaimInterface
    {
        return $this->get($name, $this->{$name}());
    }

    /**
     * Add a new claim mapping.
     *
     * @return $this
     */
    public function extend(string $name, string $classPath)
    {
        $this->classMap[$name] = $classPath;

        return $this;
    }

    /**
     * Set the token ttl (in seconds).
     *
     * @return $this
     */
    public function setTtl(?int $ttl)
    {
        $this->ttl = $ttl === null ? null : (int) $ttl;

        return $this;
    }

    /**
     * Get the token ttl.
     */
    public function getTtl(): ?int
    {
        return $this->ttl;
    }

    /**
     * Set the token refresh ttl (in seconds).
     *
     * @return $this
     */
    public function setRefreshTtl(?int $refreshTtl)
    {
        $this->refreshTtl = $refreshTtl === null ? null : (int) $refreshTtl;

        return $this;
    }

    /**
     * Get the token refresh ttl.
     */
    public function getRefreshTtl(): ?int
    {
        return $this->refreshTtl;
    }

    /**
     * Set the leeway in seconds.
     *
     * @return $this
     */
    public function setLeeway(int $leeway)
    {
        $this->leeway = $leeway;

        return $this;
    }

    public function iss(): string
    {
        return ApplicationContext::getContainer()->get(ServerRequestInterface::class)->url();
    }

    public function iat(): int
    {
        return time();
    }

    public function exp(): int
    {
        return time() + $this->getTtl();
    }

    public function nbf(): int
    {
        return time();
    }

    public function jti(): string
    {
        return Str::random(16);
    }
}
