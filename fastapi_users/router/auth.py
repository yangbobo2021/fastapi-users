from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from fastapi_users import models
from fastapi_users.authentication import AuthenticationBackend, Authenticator, Strategy
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.openapi import OpenAPIResponseType
from fastapi_users.router.common import ErrorCode, ErrorModel


def get_auth_router(
    backend: AuthenticationBackend[models.UP, models.ID],
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    authenticator: Authenticator[models.UP, models.ID],
    requires_verification: bool = False,
) -> APIRouter:
    """Generate a router with login/logout routes for an authentication backend."""
    router = APIRouter()
    get_current_user_token = authenticator.current_user_token(
        active=True, verified=requires_verification
    )

    login_responses: OpenAPIResponseType = {
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorModel,
            "content": {
                "application/json": {
                    "examples": {
                        ErrorCode.LOGIN_BAD_CREDENTIALS: {
                            "summary": "Bad credentials or the user is inactive.",
                            "value": {"detail": ErrorCode.LOGIN_BAD_CREDENTIALS},
                        },
                        ErrorCode.LOGIN_USER_NOT_VERIFIED: {
                            "summary": "The user is not verified.",
                            "value": {"detail": ErrorCode.LOGIN_USER_NOT_VERIFIED},
                        },
                    }
                }
            },
        },
        **backend.transport.get_openapi_login_responses_success(),
    }

    @router.post(
        "/login",
        name=f"auth:{backend.name}.login",
        responses=login_responses,
        description="""
        用户登录接口。
        
        此接口接收用户凭证并返回访问令牌（access token）。
        
        请求体应包含以下表单数据：
        - username: 用户名，通常是用户的电子邮件地址
        - password: 用户密码
        
        成功登录后将返回：
        - access_token: 访问令牌，用于后续请求的身份验证
        - token_type: 令牌类型，通常为"bearer"
        
        使用方法：登录成功后，在后续请求中将access_token添加到请求头的Authorization字段中，
        格式为 "Bearer {access_token}"
        
        例如：Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        
        注意：如果启用了验证要求（requires_verification=True），未验证的用户将无法登录。
        """,
    )
    async def login(
        request: Request,
        credentials: OAuth2PasswordRequestForm = Depends(),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
        strategy: Strategy[models.UP, models.ID] = Depends(backend.get_strategy),
    ):
        user = await user_manager.authenticate(credentials)

        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.LOGIN_BAD_CREDENTIALS,
            )
        if requires_verification and not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.LOGIN_USER_NOT_VERIFIED,
            )
        response = await backend.login(strategy, user)
        await user_manager.on_after_login(user, request, response)
        return response

    logout_responses: OpenAPIResponseType = {
        **{
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user."
            }
        },
        **backend.transport.get_openapi_logout_responses_success(),
    }

    @router.post(
        "/logout",
        name=f"auth:{backend.name}.logout",
        responses=logout_responses,
        description="""
        用户登出接口。
        
        此接口使当前用户的访问令牌失效，实现安全登出。
        
        请求需要包含有效的Authorization请求头，格式为 "Bearer {access_token}"，
        其中access_token是之前登录时获取的令牌。
        
        成功登出后，之前的访问令牌将不再有效，需要重新登录获取新的令牌。
        
        注意：
        - 此请求必须是已认证状态（需要有效的访问令牌）
        - 如果令牌缺失或已失效，将返回401 Unauthorized错误
        - 登出后，使用相同令牌的后续请求将被拒绝
        """,
    )
    async def logout(
        user_token: tuple[models.UP, str] = Depends(get_current_user_token),
        strategy: Strategy[models.UP, models.ID] = Depends(backend.get_strategy),
    ):
        user, token = user_token
        return await backend.logout(strategy, user, token)

    return router
