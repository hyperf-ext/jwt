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

use Hyperf\Utils\Collection as HyperfCollection;

class Collection extends HyperfCollection
{
    /**
     * Create a new collection.
     *
     * @param mixed $items
     */
    public function __construct($items = [])
    {
        parent::__construct($this->getArrayableItems($items));
    }

    /**
     * Get a Claim instance by it's unique name.
     *
     * @param mixed $default
     */
    public function getByClaimName(string $name, ?callable $callback = null, $default = null): AbstractClaim
    {
        return $this->filter(function (AbstractClaim $claim) use ($name) {
            return $claim->getName() === $name;
        })->first($callback, $default);
    }

    /**
     * Validate each claim.
     *
     * @return $this
     */
    public function validate(bool $ignoreExpired = false)
    {
        $this->each(function ($claim) use ($ignoreExpired) {
            $claim->validate($ignoreExpired);
        });
        return $this;
    }

    /**
     * Determine if the Collection contains all of the given keys.
     *
     * @param mixed $claims
     */
    public function hasAllClaims($claims): bool
    {
        return count($claims) and (new static($claims))->diff($this->keys())->isEmpty();
    }

    /**
     * Get the claims as key/val array.
     */
    public function toPlainArray(): array
    {
        return $this->map(function (AbstractClaim $claim) {
            return $claim->getValue();
        })->toArray();
    }

    /**
     * {@inheritdoc}
     */
    protected function getArrayableItems($items): array
    {
        return $this->sanitizeClaims($items);
    }

    /**
     * Ensure that the given claims array is keyed by the claim name.
     *
     * @param mixed $items
     */
    private function sanitizeClaims($items): array
    {
        $claims = [];
        foreach ($items as $key => $value) {
            if (! is_string($key) and $value instanceof AbstractClaim) {
                $key = $value->getName();
            }

            $claims[$key] = $value;
        }

        return $claims;
    }
}
