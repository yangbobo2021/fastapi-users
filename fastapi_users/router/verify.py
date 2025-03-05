from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import EmailStr

from fastapi_users import exceptions, models, schemas
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.router.common import ErrorCode, ErrorModel


def get_verify_router(
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    user_schema: type[schemas.U],
):
    router = APIRouter()

    @router.post(
        "/request-verify-token",
        status_code=status.HTTP_202_ACCEPTED,
        name="verify:request-token",
        description="""
        请求用户电子邮件验证令牌。
        
        此接口允许用户请求一个验证令牌，用于验证其电子邮件地址的真实性和所有权。
        
        请求体：
        - email: 需要验证的电子邮件地址
        
        处理流程：
        1. 系统检查提供的电子邮件是否对应一个已注册的用户
        2. 如果用户存在且未验证，系统生成一个验证令牌
        3. 系统发送包含验证链接的电子邮件到用户的邮箱（链接中包含验证令牌）
        
        安全特性：
        - 无论电子邮件是否存在于系统中，接口都返回 202 Accepted 状态码
        - 这种设计防止攻击者通过接口响应来探测系统中存在的用户账号
        - 如果用户账号已被停用（inactive）或已验证（verified），系统不会发送验证邮件，但仍返回成功
        
        返回：
        - 无返回内容，状态码 202 Accepted 表示请求已被接受处理
        
        注意：实际的电子邮件验证需要用户点击邮件中的链接，然后使用 /verify 接口完成。
        """,
    )
    async def request_verify_token(
        request: Request,
        email: EmailStr = Body(..., embed=True),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        try:
            user = await user_manager.get_by_email(email)
            await user_manager.request_verify(user, request)
        except (
            exceptions.UserNotExists,
            exceptions.UserInactive,
            exceptions.UserAlreadyVerified,
        ):
            pass

        return None

    @router.post(
        "/verify",
        response_model=user_schema,
        name="verify:verify",
        description="""
        验证用户电子邮件地址。
        
        此接口使用从验证邮件中获得的令牌来确认用户电子邮件地址的真实性和所有权。
        
        请求体：
        - token: 电子邮件验证令牌，通常从验证邮件中的链接获取
        
        处理流程：
        1. 系统验证令牌的有效性和过期状态
        2. 检查令牌对应的用户是否存在
        3. 如果验证成功，系统将用户标记为已验证（is_verified=True）
        
        可能的错误：
        - 400 Bad Request: 令牌无效、已过期或对应的用户不存在
        - 400 Bad Request: 用户已经完成了验证
        
        成功响应：
        - 200 OK，返回已验证用户的完整信息
        
        返回数据：
        - id: 用户唯一标识符
        - email: 用户电子邮件地址
        - is_active: 用户账号是否处于活跃状态
        - is_superuser: 用户是否拥有超级管理员权限
        - is_verified: 用户账号是否已验证（此时应为 true）
        - 其他可能的自定义用户字段
        
        安全建议：
        - 验证令牌通常有时间限制，过期后需要重新请求
        - 验证成功后，可能需要刷新用户的会话令牌
        - 某些系统功能可能仅对已验证用户开放
        
        使用场景：
        - 完成新用户注册流程
        - 验证用户更改的电子邮件地址
        - 提高账号安全性和防止垃圾注册
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            ErrorCode.VERIFY_USER_BAD_TOKEN: {
                                "summary": "Bad token, not existing user or"
                                "not the e-mail currently set for the user.",
                                "value": {"detail": ErrorCode.VERIFY_USER_BAD_TOKEN},
                            },
                            ErrorCode.VERIFY_USER_ALREADY_VERIFIED: {
                                "summary": "The user is already verified.",
                                "value": {
                                    "detail": ErrorCode.VERIFY_USER_ALREADY_VERIFIED
                                },
                            },
                        }
                    }
                },
            }
        },
    )
    async def verify(
        request: Request,
        token: str = Body(..., embed=True),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        try:
            user = await user_manager.verify(token, request)
            return schemas.model_validate(user_schema, user)
        except (exceptions.InvalidVerifyToken, exceptions.UserNotExists):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_BAD_TOKEN,
            )
        except exceptions.UserAlreadyVerified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_ALREADY_VERIFIED,
            )

    return router
