<?php
/**
 * Created by IntelliJ IDEA.
 * User: yuanc
 * Date: 2018/4/12
 * Time: 10:45
 */

namespace YuanChang\LumenPassport;


use Illuminate\Support\Facades\Redis;
use League\OAuth2\Server\Exception\OAuthServerException;

class MobileCheckManager implements MobileChecker
{
    public function check($mobile, $code)
    {
        $key = "mobile:". $mobile;
        if (Redis::exists($key) && Redis::get($key) == $code)
            return true;
        return false;
    }
}