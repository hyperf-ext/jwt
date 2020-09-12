<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfTest\Claims;

use HyperfExt\Jwt\Claims\NotBefore;
use HyperfExt\Jwt\Exceptions\InvalidClaimException;
use HyperfTest\AbstractTestCase;

/**
 * @internal
 * @coversNothing
 */
class NotBeforeTest extends AbstractTestCase
{
    /**
     * @test
     */
    public function itShouldThrowAnExceptionWhenPassingAnInvalidValue()
    {
        $this->expectExceptionMessage('Invalid value provided for claim [nbf]');
        $this->expectException(InvalidClaimException::class);
        new NotBefore('foo');
    }
}
