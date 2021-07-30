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

use Exception;
use Hyperf\Utils\Arr;
use Hyperf\Utils\Collection;
use HyperfExt\Jwt\Contracts\CodecInterface;
use HyperfExt\Jwt\Exceptions\JwtException;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

class Codec implements CodecInterface
{
    /**
     * Signers that this provider supports.
     *
     * @var array
     */
    protected $signers = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];

    protected $asymmetric = [
        'HS256' => false,
        'HS384' => false,
        'HS512' => false,
        'RS256' => true,
        'RS384' => true,
        'RS512' => true,
        'ES256' => true,
        'ES384' => true,
        'ES512' => true,
    ];

    /**
     * The secret.
     *
     * @var string
     */
    protected $secret;

    /**
     * The array of keys.
     *
     * @var array
     */
    protected $keys;

    /**
     * The used algorithm.
     *
     * @var string
     */
    protected $algo;

    /**
     * The Configuration instance.
     *
     * @var \Lcobucci\JWT\Configuration
     */
    protected $config;

    /**
     * The Signer instance.
     *
     * @var \Lcobucci\JWT\Signer
     */
    protected $signer;

    /**
     * @param null|\Lcobucci\JWT\Configuration $config
     *
     * @throws \HyperfExt\Jwt\Exceptions\JwtException
     */
    public function __construct(string $secret, string $algo, array $keys, $config = null)
    {
        $this->secret = $secret;
        $this->algo = $algo;
        $this->keys = $keys;
        $this->config = $config;

        $this->signer = $this->getSigner();

        if (! is_null($config)) {
            $this->config = $config;
        } elseif ($this->isAsymmetric()) {
            $this->config = Configuration::forAsymmetricSigner($this->signer, $this->getSigningKey(), $this->getVerificationKey());
        } else {
            $this->config = Configuration::forSymmetricSigner($this->signer, InMemory::plainText($this->getSecret()));
        }
        if (! count($this->config->validationConstraints())) {
            $this->config->setValidationConstraints(
                new SignedWith($this->signer, $this->getVerificationKey()),
            );
        }
    }

    /**
     * Set the algorithm used to sign the token.
     *
     * @return $this
     */
    public function setAlgo(string $algo)
    {
        $this->algo = $algo;

        return $this;
    }

    /**
     * Get the algorithm used to sign the token.
     */
    public function getAlgo(): string
    {
        return $this->algo;
    }

    /**
     * Set the secret used to sign the token.
     *
     * @return $this
     */
    public function setSecret(string $secret)
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * Get the secret used to sign the token.
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Set the keys used to sign the token.
     *
     * @return $this
     */
    public function setKeys(array $keys)
    {
        $this->keys = $keys;

        return $this;
    }

    /**
     * Get the array of keys used to sign tokens
     * with an asymmetric algorithm.
     */
    public function getKeys(): array
    {
        return $this->keys;
    }

    /**
     * Get the public key used to sign tokens
     * with an asymmetric algorithm.
     *
     * @return resource|string
     */
    public function getPublicKey()
    {
        return Arr::get($this->keys, 'public');
    }

    /**
     * Get the private key used to sign tokens
     * with an asymmetric algorithm.
     *
     * @return resource|string
     */
    public function getPrivateKey()
    {
        return Arr::get($this->keys, 'private');
    }

    /**
     * Get the passphrase used to sign tokens
     * with an asymmetric algorithm.
     */
    public function getPassphrase(): ?string
    {
        return Arr::get($this->keys, 'passphrase');
    }

    /**
     * Create a JSON Web Token.
     *
     * @throws \HyperfExt\Jwt\Exceptions\JwtException
     */
    public function encode(array $payload): string
    {
        $builder = $this->getBuilder();

        try {
            foreach ($payload as $key => $value) {
                $this->addClaim($builder, $key, $value);
            }
            return $builder->getToken($this->config->signer(), $this->config->signingKey())->toString();
        } catch (Exception $e) {
            throw new JwtException('Could not create token: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @throws \HyperfExt\Jwt\Exceptions\JwtException
     */
    public function decode(string $token): array
    {
        $parser = $this->getParser();

        try {
            $jwt = $parser->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), $e->getCode(), $e);
        }

        if (! $this->config->validator()->validate($jwt, ...$this->config->validationConstraints())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }
        return (new Collection($jwt->claims()->all()))->map(function ($claim) {
            if (is_a($claim, \DateTimeImmutable::class)) {
                return $claim->getTimestamp();
            }
            if (is_object($claim) && method_exists($claim, 'getValue')) {
                return $claim->getValue();
            }

            return $claim;
        })->toArray();
    }

    /**
     * Gets the {@see $config} attribute.
     *
     * @return \Lcobucci\JWT\Configuration
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * Adds a claim to the {@see $config}.
     *
     * @param mixed $value
     */
    protected function addClaim(Builder $builder, string $key, $value)
    {
        switch ($key) {
            case RegisteredClaims::ID:
                $builder->identifiedBy((string) $value);
                break;
            case RegisteredClaims::EXPIRATION_TIME:
                $builder->expiresAt(\DateTimeImmutable::createFromFormat('U', (string) $value));
                break;
            case RegisteredClaims::NOT_BEFORE:
                $builder->canOnlyBeUsedAfter(\DateTimeImmutable::createFromFormat('U', (string) $value));
                break;
            case RegisteredClaims::ISSUED_AT:
                $builder->issuedAt(\DateTimeImmutable::createFromFormat('U', (string) $value));
                break;
            case RegisteredClaims::ISSUER:
                $builder->issuedBy((string) $value);
                break;
            case RegisteredClaims::AUDIENCE:
                $builder->permittedFor((string) $value);
                break;
            case RegisteredClaims::SUBJECT:
                $builder->relatedTo((string) $value);
                break;
            default:
                $builder->withClaim($key, $value);
        }
    }

    /**
     * Get the signer instance.
     *
     * @throws \HyperfExt\Jwt\Exceptions\JwtException
     */
    protected function getSigner(): Signer
    {
        if ($this->signer !== null) {
            return $this->signer;
        }

        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JwtException('The given algorithm could not be found');
        }

        return $this->signer = new $this->signers[$this->algo]();
    }

    /**
     * Get the builder instance.
     */
    protected function getBuilder(): Builder
    {
        return $this->config->builder();
    }

    /**
     * Get the parser instance.
     */
    protected function getParser(): Parser
    {
        return $this->config->parser();
    }

    /**
     * Determine if the algorithm is asymmetric, and thus
     * requires a public/private key combo.
     */
    protected function isAsymmetric(): bool
    {
        return $this->asymmetric[$this->algo];
    }

    /**
     * Get the key used to sign the tokens.
     */
    protected function getSigningKey(): Signer\Key
    {
        return $this->isAsymmetric()
            ? InMemory::plainText($this->getPrivateKey(), $this->getPassphrase() ?? '')
            : InMemory::plainText($this->getSecret());
    }

    /**
     * Get the key used to verify the tokens.
     */
    protected function getVerificationKey(): Signer\Key
    {
        return $this->isAsymmetric()
            ? InMemory::plainText($this->getPublicKey())
            : InMemory::plainText($this->getSecret());
    }
}
