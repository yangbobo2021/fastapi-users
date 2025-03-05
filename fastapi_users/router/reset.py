from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import EmailStr

from fastapi_users import exceptions, models
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.openapi import OpenAPIResponseType
from fastapi_users.router.common import ErrorCode, ErrorModel

RESET_PASSWORD_RESPONSES: OpenAPIResponseType = {
    status.HTTP_400_BAD_REQUEST: {
        "model": ErrorModel,
        "content": {
            "application/json": {
                "examples": {
                    ErrorCode.RESET_PASSWORD_BAD_TOKEN: {
                        "summary": "Bad or expired token.",
                        "value": {"detail": ErrorCode.RESET_PASSWORD_BAD_TOKEN},
                    },
                    ErrorCode.RESET_PASSWORD_INVALID_PASSWORD: {
                        "summary": "Password validation failed.",
                        "value": {
                            "detail": {
                                "code": ErrorCode.RESET_PASSWORD_INVALID_PASSWORD,
                                "reason": "Password should be at least 3 characters",
                            }
                        },
                    },
                }
            }
        },
    },
}


def get_reset_password_router(
    get_user_manager: UserManagerDependency[models.UP, models.ID],
) -> APIRouter:
    """Generate a router with the reset password routes."""
    router = APIRouter()

    @router.post(
        "/forgot-password",
        status_code=status.HTTP_202_ACCEPTED,
        name="reset:forgot_password",
        description="""
        请求密码重置。
        
        此接口允许用户通过提供注册的电子邮件地址来请求密码重置。
        
        请求体：
        - email: 用户注册的电子邮件地址
        
        处理流程：
        1. 系统验证提供的电子邮件是否对应一个有效的用户账号
        2. 如果用户存在且处于活跃状态，系统将生成一个密码重置令牌
        3. 系统发送包含重置链接的电子邮件到用户的邮箱（链接中包含重置令牌）
        
        安全特性：
        - 无论电子邮件是否存在于系统中，接口都返回 202 Accepted 状态码
        - 这种设计防止攻击者通过接口响应来探测系统中存在的用户账号
        - 如果用户账号已被停用（inactive），系统不会发送重置邮件，但仍返回成功
        
        返回：
        - 无返回内容，状态码 202 Accepted 表示请求已被接受处理
        
        注意：实际的密码重置需要用户点击邮件中的链接，然后使用 /reset-password 接口完成。
        """,
    )
    async def forgot_password(
        request: Request,
        email: EmailStr = Body(..., embed=True),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        try:
            user = await user_manager.get_by_email(email)
        except exceptions.UserNotExists:
            return None

        try:
            await user_manager.forgot_password(user, request)
        except exceptions.UserInactive:
            pass

        return None

    @router.post(
        "/reset-password",
        name="reset:reset_password",
        description="""
        重置用户密码。
        
        此接口使用从 forgot-password 流程中获得的令牌来重置用户密码。
        
        请求体：
        - token: 密码重置令牌，通常从重置邮件中的链接获取
        - password: 用户希望设置的新密码
        
        处理流程：
        1. 系统验证重置令牌的有效性和过期状态
        2. 检查令牌对应的用户是否存在且处于活跃状态
        3. 验证新密码是否符合系统的密码策略
        4. 更新用户密码并使所有现有会话失效
        
        可能的错误：
        - 400 Bad Request: 令牌无效或已过期
        - 400 Bad Request: 用户不存在或已被停用
        - 400 Bad Request: 新密码不符合系统要求（如密码过短）
        
        成功响应：
        - 200 OK，表示密码已成功重置
        
        安全建议：
        - 重置令牌通常有时间限制，过期后需要重新请求
        - 密码重置成功后，用户应使用新密码重新登录
        - 为提高安全性，系统可能会通知用户密码已被更改
        """,
        responses=RESET_PASSWORD_RESPONSES,
    )
    async def reset_password(
        request: Request,
        token: str = Body(...),
        password: str = Body(...),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        try:
            await user_manager.reset_password(token, password, request)
        except (
            exceptions.InvalidResetPasswordToken,
            exceptions.UserNotExists,
            exceptions.UserInactive,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.RESET_PASSWORD_BAD_TOKEN,
            )
        except exceptions.InvalidPasswordException as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": ErrorCode.RESET_PASSWORD_INVALID_PASSWORD,
                    "reason": e.reason,
                },
            )

    return router
