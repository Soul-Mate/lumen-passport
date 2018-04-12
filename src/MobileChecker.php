<?php
/**
 * Created by IntelliJ IDEA.
 * User: yuanc
 * Date: 2018/4/12
 * Time: 10:39
 */

namespace YuanChang\LumenPassport;


interface MobileChecker
{
    public function check($mobile, $code);
}