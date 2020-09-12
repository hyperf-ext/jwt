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
use Hyperf\Utils\Contracts\Arrayable;
use Hyperf\Utils\Contracts\Jsonable;
use HyperfExt\Jwt\Contracts\ClaimInterface;
use HyperfExt\Jwt\Contracts\ManagerInterface;
use JsonSerializable;

abstract class AbstractClaim implements ClaimInterface, Arrayable, Jsonable, JsonSerializable
{
    /**
     * The claim name.
     *
     * @var string
     */
    protected $name;

    /**
     * The claim value.
     *
     * @var mixed
     */
    private $value;

    /**
     * @var \HyperfExt\Jwt\Claims\Factory
     */
    private $factory;

    /**
     * @param mixed $value
     */
    public function __construct($value)
    {
        $this->setValue($value);
    }

    /**
     * Get the payload as a string.
     */
    public function __toString(): string
    {
        return $this->toJson();
    }

    /**
     * Set the claim value, and call a validate method.
     *
     * @param mixed $value
     *
     * @return $this
     */
    public function setValue($value)
    {
        $this->value = $this->validateCreate($value);

        return $this;
    }

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Set the claim name.
     *
     * @return $this
     */
    public function setName(string $name)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get the claim name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Validate the claim in a standalone Claim context.
     *
     * @param mixed $value
     */
    public function validateCreate($value)
    {
        return $value;
    }

    /**
     * Checks if the value matches the claim.
     *
     * @param mixed $value
     */
    public function matches($value, bool $strict = true): bool
    {
        return $strict ? $this->value === $value : $this->value == $value;
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Build a key value array comprising of the claim name and value.
     */
    public function toArray(): array
    {
        return [$this->getName() => $this->getValue()];
    }

    /**
     * Get the claim as JSON.
     */
    public function toJson(int $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    protected function getFactory(): Factory
    {
        if (! empty($this->factory)) {
            return $this->factory;
        }
        return $this->factory = ApplicationContext::getContainer()->get(ManagerInterface::class)->getClaimFactory();
    }
}
