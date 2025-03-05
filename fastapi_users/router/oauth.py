from typing import Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from httpx_oauth.integrations.fastapi import OAuth2AuthorizeCallback
from httpx_oauth.oauth2 import BaseOAuth2, OAuth2Token
from pydantic import BaseModel

from fastapi_users import models, schemas
from fastapi_users.authentication import AuthenticationBackend, Authenticator, Strategy
from fastapi_users.exceptions import UserAlreadyExists
from fastapi_users.jwt import SecretType, decode_jwt, generate_jwt
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.router.common import ErrorCode, ErrorModel

STATE_TOKEN_AUDIENCE = "fastapi-users:oauth-state"


class OAuth2AuthorizeResponse(BaseModel):
    authorization_url: str


def generate_state_token(
    data: dict[str, str], secret: SecretType, lifetime_seconds: int = 3600
) -> str:
    data["aud"] = STATE_TOKEN_AUDIENCE
    return generate_jwt(data, secret, lifetime_seconds)


def get_oauth_router(
    oauth_client: BaseOAuth2,
    backend: AuthenticationBackend[models.UP, models.ID],
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    state_secret: SecretType,
    redirect_url: Optional[str] = None,
    associate_by_email: bool = False,
    is_verified_by_default: bool = False,
) -> APIRouter:
    """Generate a router with the OAuth routes."""
    router = APIRouter()
    callback_route_name = f"oauth:{oauth_client.name}.{backend.name}.callback"

    if redirect_url is not None:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            redirect_url=redirect_url,
        )
    else:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            route_name=callback_route_name,
        )

    @router.get(
        "/authorize",
        name=f"oauth:{oauth_client.name}.{backend.name}.authorize",
        response_model=OAuth2AuthorizeResponse,
        description="""
        OAuth 授权重定向接口。
        
        此接口将用户重定向到第三方 OAuth 提供商（如 Google、Facebook、GitHub 等）进行身份验证。
        
        请求参数：
        - scopes: 可选，指定请求的 OAuth 权限范围，例如 ["email", "profile"]
        
        流程说明：
        1. 调用此接口会生成一个包含状态令牌(state token)的授权 URL
        2. 前端应将用户重定向到返回的 authorization_url
        3. 用户在 OAuth 提供商页面完成身份验证后，会被重定向回系统的 callback 接口
        
        返回内容：
        - authorization_url: 完整的 OAuth 授权 URL，前端应将用户重定向到此 URL
        
        注意：状态令牌有效期为 1 小时，用于防止跨站请求伪造(CSRF)攻击。
        """,
    )
    async def authorize(
        request: Request, scopes: list[str] = Query(None)
    ) -> OAuth2AuthorizeResponse:
        if redirect_url is not None:
            authorize_redirect_url = redirect_url
        else:
            authorize_redirect_url = str(request.url_for(callback_route_name))

        state_data: dict[str, str] = {}
        state = generate_state_token(state_data, state_secret)
        authorization_url = await oauth_client.get_authorization_url(
            authorize_redirect_url,
            state,
            scopes,
        )

        return OAuth2AuthorizeResponse(authorization_url=authorization_url)

    @router.get(
        "/callback",
        name=callback_route_name,
        description="""
        OAuth 授权回调接口。
        
        此接口处理 OAuth 提供商在用户完成身份验证后的回调请求。通常由 OAuth 提供商自动调用，不需要手动访问。
        
        请求参数（由 OAuth 提供商自动添加）：
        - code: OAuth 授权码
        - state: 状态令牌，用于验证请求的合法性
        
        处理流程：
        1. 验证状态令牌的有效性
        2. 使用授权码从 OAuth 提供商获取访问令牌
        3. 获取用户在 OAuth 提供商的账号信息（ID 和电子邮件）
        4. 在系统中创建或关联用户账号
        5. 生成系统的身份验证令牌并返回
        
        可能的错误：
        - 400 Bad Request: 状态令牌无效
        - 400 Bad Request: OAuth 提供商未返回电子邮件
        - 400 Bad Request: 用户账号已存在（当尝试创建新账号时）
        - 400 Bad Request: 用户账号未激活
        
        成功响应：根据使用的身份验证后端不同而异，通常包含访问令牌和令牌类型。
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            "INVALID_STATE_TOKEN": {
                                "summary": "Invalid state token.",
                                "value": None,
                            },
                            ErrorCode.LOGIN_BAD_CREDENTIALS: {
                                "summary": "User is inactive.",
                                "value": {"detail": ErrorCode.LOGIN_BAD_CREDENTIALS},
                            },
                        }
                    }
                },
            },
        },
    )
    async def callback(
        request: Request,
        access_token_state: tuple[OAuth2Token, str] = Depends(
            oauth2_authorize_callback
        ),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
        strategy: Strategy[models.UP, models.ID] = Depends(backend.get_strategy),
    ):
        token, state = access_token_state
        account_id, account_email = await oauth_client.get_id_email(
            token["access_token"]
        )

        if account_email is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
            )

        try:
            decode_jwt(state, state_secret, [STATE_TOKEN_AUDIENCE])
        except jwt.DecodeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        try:
            user = await user_manager.oauth_callback(
                oauth_client.name,
                token["access_token"],
                account_id,
                account_email,
                token.get("expires_at"),
                token.get("refresh_token"),
                request,
                associate_by_email=associate_by_email,
                is_verified_by_default=is_verified_by_default,
            )
        except UserAlreadyExists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_USER_ALREADY_EXISTS,
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.LOGIN_BAD_CREDENTIALS,
            )

        # Authenticate
        response = await backend.login(strategy, user)
        await user_manager.on_after_login(user, request, response)
        return response

    return router


def get_oauth_associate_router(
    oauth_client: BaseOAuth2,
    authenticator: Authenticator[models.UP, models.ID],
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    user_schema: type[schemas.U],
    state_secret: SecretType,
    redirect_url: Optional[str] = None,
    requires_verification: bool = False,
) -> APIRouter:
    """Generate a router with the OAuth routes to associate an authenticated user."""
    router = APIRouter()

    get_current_active_user = authenticator.current_user(
        active=True, verified=requires_verification
    )

    callback_route_name = f"oauth-associate:{oauth_client.name}.callback"

    if redirect_url is not None:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            redirect_url=redirect_url,
        )
    else:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            route_name=callback_route_name,
        )

    @router.get(
        "/authorize",
        name=f"oauth-associate:{oauth_client.name}.authorize",
        response_model=OAuth2AuthorizeResponse,
        description="""
        关联 OAuth 账号的授权重定向接口。
        
        此接口允许已登录用户将其账号与第三方 OAuth 提供商（如 Google、Facebook、GitHub 等）的账号关联。
        
        请求参数：
        - scopes: 可选，指定请求的 OAuth 权限范围，例如 ["email", "profile"]
        
        请求头要求：
        - Authorization: Bearer {access_token}，用户必须已登录才能关联账号
        
        流程说明：
        1. 系统验证用户已登录
        2. 生成包含用户 ID 的状态令牌和授权 URL
        3. 前端应将用户重定向到返回的 authorization_url
        4. 用户在 OAuth 提供商页面完成身份验证后，会被重定向回系统的 callback 接口
        
        返回内容：
        - authorization_url: 完整的 OAuth 授权 URL，前端应将用户重定向到此 URL
        
        注意：用户必须处于已登录状态才能使用此接口。状态令牌中包含用户 ID，以确保回调时的安全性。
        """,
    )
    async def authorize(
        request: Request,
        scopes: list[str] = Query(None),
        user: models.UP = Depends(get_current_active_user),
    ) -> OAuth2AuthorizeResponse:
        if redirect_url is not None:
            authorize_redirect_url = redirect_url
        else:
            authorize_redirect_url = str(request.url_for(callback_route_name))

        state_data: dict[str, str] = {"sub": str(user.id)}
        state = generate_state_token(state_data, state_secret)
        authorization_url = await oauth_client.get_authorization_url(
            authorize_redirect_url,
            state,
            scopes,
        )

        return OAuth2AuthorizeResponse(authorization_url=authorization_url)

    @router.get(
        "/callback",
        response_model=user_schema,
        name=callback_route_name,
        description="""
        关联 OAuth 账号的回调接口。
        
        此接口处理 OAuth 提供商在用户完成身份验证后的回调请求，用于将当前登录用户与 OAuth 账号关联。
        通常由 OAuth 提供商自动调用，不需要手动访问。
        
        请求参数（由 OAuth 提供商自动添加）：
        - code: OAuth 授权码
        - state: 状态令牌，包含用户 ID，用于验证请求的合法性
        
        请求头要求：
        - Authorization: Bearer {access_token}，用户必须已登录
        
        处理流程：
        1. 验证用户已登录且状态令牌有效
        2. 确认状态令牌中的用户 ID 与当前登录用户一致
        3. 使用授权码从 OAuth 提供商获取访问令牌
        4. 获取用户在 OAuth 提供商的账号信息（ID 和电子邮件）
        5. 将 OAuth 账号信息关联到当前用户账号
        
        可能的错误：
        - 400 Bad Request: 状态令牌无效
        - 400 Bad Request: 状态令牌中的用户 ID 与当前登录用户不匹配
        - 400 Bad Request: OAuth 提供商未返回电子邮件
        - 401 Unauthorized: 用户未登录或会话已过期
        
        成功响应：返回更新后的用户信息，包含新关联的 OAuth 账号详情
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            "INVALID_STATE_TOKEN": {
                                "summary": "Invalid state token.",
                                "value": None,
                            },
                        }
                    }
                },
            },
        },
    )
    async def callback(
        request: Request,
        user: models.UP = Depends(get_current_active_user),
        access_token_state: tuple[OAuth2Token, str] = Depends(
            oauth2_authorize_callback
        ),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        token, state = access_token_state
        account_id, account_email = await oauth_client.get_id_email(
            token["access_token"]
        )

        if account_email is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
            )

        try:
            state_data = decode_jwt(state, state_secret, [STATE_TOKEN_AUDIENCE])
        except jwt.DecodeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        if state_data["sub"] != str(user.id):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        user = await user_manager.oauth_associate_callback(
            user,
            oauth_client.name,
            token["access_token"],
            account_id,
            account_email,
            token.get("expires_at"),
            token.get("refresh_token"),
            request,
        )

        return schemas.model_validate(user_schema, user)

    return router
