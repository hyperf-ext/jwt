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

use HyperfExt\Jwt\Claims\Collection;
use HyperfExt\Jwt\Claims\Expiration;
use HyperfExt\Jwt\Claims\IssuedAt;
use HyperfExt\Jwt\Claims\Issuer;
use HyperfExt\Jwt\Claims\JwtId;
use HyperfExt\Jwt\Claims\NotBefore;
use HyperfExt\Jwt\Claims\Subject;
use HyperfTest\AbstractTestCase;

/**
 * @internal
 * @coversNothing
 */
class CollectionTest extends AbstractTestCase
{
    /** @test */
    public function itShouldSanitizeTheClaimsToAssociativeArray()
    {
        $collection = $this->getCollection();

        $this->assertSame(array_keys($collection->toArray()), ['sub', 'iss', 'exp', 'nbf', 'iat', 'jti']);
    }

    /** @test */
    public function itShouldDetermineIfACollectionContainsAllTheGivenClaims()
    {
        $collection = $this->getCollection();

        $this->assertFalse($collection->hasAllClaims(['sub', 'iss', 'exp', 'nbf', 'iat', 'jti', 'abc']));
        $this->assertFalse($collection->hasAllClaims(['foo', 'bar']));
        $this->assertFalse($collection->hasAllClaims([]));

        $this->assertTrue($collection->hasAllClaims(['sub', 'iss']));
        $this->assertTrue($collection->hasAllClaims(['sub', 'iss', 'exp', 'nbf', 'iat', 'jti']));
    }

    /** @test */
    public function itShouldGetAClaimInstanceByName()
    {
        $collection = $this->getCollection();

        $this->assertInstanceOf(Expiration::class, $collection->getByClaimName('exp'));
        $this->assertInstanceOf(Subject::class, $collection->getByClaimName('sub'));
    }

    private function getCollection()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        return new Collection($claims);
    }
}
