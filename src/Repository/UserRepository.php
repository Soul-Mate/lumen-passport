<?php

namespace YuanChang\LumenPassport\Repository;

use RuntimeException;
use Laravel\Passport\Bridge\User;
use YuanChang\LumenPassport\MobileChecker;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;

class UserRepository implements UserRepositoryInterface
{
    public function getUserEntityByUserCredentials(
        $mobile,
        $code,
        $grantType,
        ClientEntityInterface $clientEntity
    )
    {
        if ($grantType != "mobile")
            throw OAuthServerException::invalidGrant($grantType);
        $provider = config('auth.guards.api.provider');

        if (is_null($model = config('auth.providers.' . $provider . '.model')))
            throw new RuntimeException('Unable to determine authentication model from configuration.');

        if (method_exists($model, "findForMobile"))
            $user = (new  $model)->findForMobile($mobile);
        else
            $user = (new $model)->where("mobile", $mobile)->first();

        if (!$user) {
            return false;
        } else if (method_exists($user, "validateForMobileVerifyCode") && !$user->validateForMobileVerifyCode($code)) {
            return false;
        } else if (($checker = app()->make(MobileChecker::class))) {
            if (!$checker->check($mobile, $code)) {
                return false;
            }
        } else {
            return false;
        }
        return new User($user->getAuthIdentifier());
    }
}