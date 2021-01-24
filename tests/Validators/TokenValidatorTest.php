<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfTest\Validators;

use HyperfExt\Jwt\Contracts\TokenValidatorInterface;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;
use HyperfTest\AbstractTestCase;

/**
 * @internal
 * @coversNothing
 */
class TokenValidatorTest extends AbstractTestCase
{
    /**
     * @var \HyperfExt\Jwt\Validators\TokenValidator
     */
    protected $validator;

    public function setUp(): void
    {
        parent::setUp();

        $this->validator = $this->container->get(TokenValidatorInterface::class);
    }

    /** @test */
    public function itShouldReturnTrueWhenProvidingAWellFormedToken()
    {
        $this->assertTrue($this->validator->isValid('one.two.three'));
    }

    public function dataProviderMalformedTokens()
    {
        return [
            ['one.two.'],
            ['.two.'],
            ['.two.three'],
            ['one..three'],
            ['..'],
            [' . . '],
            [' one . two . three '],
        ];
    }

    /**
     * @test
     * @dataProvider \HyperfTest\Validators\TokenValidatorTest::dataProviderMalformedTokens
     *
     * @param string $token
     */
    public function itShouldReturnFalseWhenProvidingAMalformedToken($token)
    {
        $this->assertFalse($this->validator->isValid($token));
    }

    /**
     * @test
     * @dataProvider \HyperfTest\Validators\TokenValidatorTest::dataProviderMalformedTokens
     *
     * @param string $token
     */
    public function itShouldThrowAnExceptionWhenProvidingAMalformedToken($token)
    {
        $this->expectExceptionMessage('Malformed token');
        $this->expectException(TokenInvalidException::class);
        $this->validator->check($token);
    }

    public function dataProviderTokensWithWrongSegmentsNumber()
    {
        return [
            ['one.two'],
            ['one.two.three.four'],
            ['one.two.three.four.five'],
        ];
    }

    /**
     * @test
     * @dataProvider \HyperfTest\Validators\TokenValidatorTest::dataProviderTokensWithWrongSegmentsNumber
     *
     * @param string $token
     */
    public function itShouldReturnFalseWhenProvidingATokenWithWrongSegmentsNumber($token)
    {
        $this->assertFalse($this->validator->isValid($token));
    }

    /**
     * @test
     * @dataProvider \HyperfTest\Validators\TokenValidatorTest::dataProviderTokensWithWrongSegmentsNumber
     *
     * @param string $token
     */
    public function itShouldThrowAnExceptionWhenProvidingAMalformedTokenWithWrongSegmentsNumber($token)
    {
        $this->expectExceptionMessage('Wrong number of segments');
        $this->expectException(TokenInvalidException::class);
        $this->validator->check($token);
    }
}
