<?php
namespace YuanChang\LumenPassport\Grants;

use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;


class MobileGrant extends AbstractGrant
{
    public function __construct(UserRepositoryInterface $userRepository,
                                RefreshTokenRepositoryInterface $refreshTokenRepository
    ){
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        // set token ttl
        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * @desc
     * @param ServerRequestInterface $request
     * @param ResponseTypeInterface $responseType
     * @param \DateInterval $accessTokenTTL
     * @author Yuanchang (yuanchang.xu@outlook.com)
     * @since 2018/4/12
     * @return ResponseTypeInterface
     * @throws OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    )
    {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));
        $user = $this->validateUser($request, $client);

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }


    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client)
    {
        $mobile = $this->getRequestParameter('mobile', $request);
        if (is_null($mobile))
            throw OAuthServerException::invalidRequest('mobile');

        $code = $this->getRequestParameter('mobile_code', $request);
        if (is_null($code))
            throw OAuthServerException::invalidRequest('mobile_code');

        // get user entity
        $user = $this->userRepository->getUserEntityByUserCredentials(
            $mobile,
            $code,
            $this->getIdentifier(),
            $client
        );

        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidCredentials();
        }
        return $user;
    }
    
    public function getIdentifier()
    {
        return "mobile";
    }
}