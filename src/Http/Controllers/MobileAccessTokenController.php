<?php
/**
 * Created by IntelliJ IDEA.
 * User: yuanc
 * Date: 2018/4/11
 * Time: 9:49
 */

namespace YuanChang\LumenPassport\Http\Controllers;

use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use YuanChang\LumenPassport\Grants\MobileGrant;
use Zend\Diactoros\Response as Psr7Response;
use Psr\Http\Message\ServerRequestInterface;
use YuanChang\LumenPassport\LumenPassport;

class MobileAccessTokenController extends AccessTokenController
{

    public function issueToken(ServerRequestInterface $request)
    {
        $response = $this->withErrorHandling(function () use ($request) {
            $input = (array) $request->getParsedBody();

            $clientId = isset($input['client_id']) ? $input['client_id'] : null;

            // Overwrite password grant at the last minute to add support for customized TTLs
            $this->server->enableGrantType(
                $this->makePasswordGrant(), LumenPassport::tokensExpireIn(null, $clientId)
            );
            return $this->server->respondToAccessTokenRequest($request, new Psr7Response);
        });

        if ($response->getStatusCode() < 200 || $response->getStatusCode() > 299) {
            return $response;
        }

        $payload = json_decode($response->getBody()->__toString(), true);

        if (isset($payload['access_token'])) {
            $tokenId = $this->jwt->parse($payload['access_token'])->getClaim('jti');
            $token = $this->tokens->find($tokenId);

            if ($token->client->firstParty() && LumenPassport::$allowMultipleTokens) {
                // We keep previous tokens for password clients
            } else {
                $this->revokeOrDeleteAccessTokens($token, $tokenId);
            }
        }

        return $response;
    }


    private function makePasswordGrant()
    {
        $grant = new MobileGrant(
            app()->make(\YuanChang\LumenPassport\Repository\UserRepository::class),
            app()->make(\Laravel\Passport\Bridge\RefreshTokenRepository::class)
        );

        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
        return $grant;
    }


    protected function revokeOrDeleteAccessTokens(Token $token, $tokenId)
    {
        $query = Token::where('user_id', $token->user_id)->where('client_id', $token->client_id);

        if ($tokenId) {
            $query->where('id', '<>', $tokenId);
        }

        if (Passport::$pruneRevokedTokens) {
            $query->delete();
        } else {
            $query->update(['revoked' => true]);
        }
    }
}