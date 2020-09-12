<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Contracts\RequestParser;

use Psr\Http\Message\ServerRequestInterface;

interface RequestParserInterface
{
    /**
     * Get the parser chain.
     *
     * @return \HyperfExt\Jwt\Contracts\RequestParser\HandlerInterface[]
     */
    public function getHandlers(): array;

    /**
     * Set the order of the parser chain.
     *
     * @param \HyperfExt\Jwt\Contracts\RequestParser\HandlerInterface[] $handlers
     *
     * @return $this
     */
    public function setHandlers(array $handlers);

    /**
     * Iterate through the parsers and attempt to retrieve
     * a value, otherwise return null.
     */
    public function parseToken(ServerRequestInterface $request): ?string;

    /**
     * Check whether a token exists in the chain.
     */
    public function hasToken(ServerRequestInterface $request): bool;
}
