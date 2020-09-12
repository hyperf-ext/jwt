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
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;

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
     * The Signer instance.
     *
     * @var \Lcobucci\JWT\Signer
     */
    protected $signer;

    public function __construct(string $secret, string $algo, array $keys)
    {
        $this->secret = $secret;
        $this->algo = $algo;
        $this->keys = $keys;
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
                $builder->withClaim($key, $value);
            }
            return (string) $builder->getToken($this->getSigner(), $this->getSigningKey());
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

        if (! $jwt->verify($this->getSigner(), $this->getVerificationKey())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return (new Collection($jwt->getClaims()))->map(function ($claim) {
            return is_object($claim) ? $claim->getValue() : $claim;
        })->toArray();
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
        return new Builder();
    }

    /**
     * Get the parser instance.
     */
    protected function getParser(): Parser
    {
        return new Parser();
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
            ? new Signer\Key($this->getPrivateKey(), $this->getPassphrase())
            : new Signer\Key($this->getSecret());
    }

    /**
     * Get the key used to verify the tokens.
     */
    protected function getVerificationKey(): Signer\Key
    {
        return $this->isAsymmetric()
            ? new Signer\Key($this->getPublicKey())
            : new Signer\Key($this->getSecret());
    }
}
