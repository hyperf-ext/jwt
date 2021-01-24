<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfTest;

use HyperfExt\Jwt\Token;

/**
 * @internal
 * @coversNothing
 */
class TokenTest extends AbstractTestCase
{
    /**
     * @var \HyperfExt\Jwt\Token
     */
    protected $token;

    public function setUp(): void
    {
        parent::setUp();

        $this->token = new Token('foo.bar.baz');
    }

    /** @test */
    public function itShouldReturnTheTokenWhenCastingToAString()
    {
        $this->assertEquals((string) $this->token, $this->token);
    }

    /** @test */
    public function itShouldReturnTheTokenWhenCallingGetMethod()
    {
        $this->assertIsString($this->token->get());
    }
}
