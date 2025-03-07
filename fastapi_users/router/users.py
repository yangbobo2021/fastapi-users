from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from fastapi_users import exceptions, models, schemas
from fastapi_users.authentication import Authenticator
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.router.common import ErrorCode, ErrorModel


def get_users_router(
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    user_schema: type[schemas.U],
    user_update_schema: type[schemas.UU],
    authenticator: Authenticator[models.UP, models.ID],
    requires_verification: bool = False,
) -> APIRouter:
    """Generate a router with the authentication routes."""
    router = APIRouter()

    get_current_active_user = authenticator.current_user(
        active=True, verified=requires_verification
    )
    get_current_superuser = authenticator.current_user(
        active=True, verified=requires_verification, superuser=True
    )

    async def get_user_or_404(
        id: str,
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ) -> models.UP:
        try:
            parsed_id = user_manager.parse_id(id)
            return await user_manager.get(parsed_id)
        except (exceptions.UserNotExists, exceptions.InvalidID) as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from e

    @router.get(
        "/me",
        response_model=user_schema,
        name="users:current_user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
        },
        description="""
        获取当前认证用户的详细信息。
        
        此接口返回当前登录用户的完整个人资料，包括用户 ID、电子邮件、权限状态等信息。
        
        请求头要求：
        - Authorization: Bearer {access_token}，必须包含有效的访问令牌
        
        返回数据：
        - id: 用户唯一标识符
        - email: 用户电子邮件地址
        - is_active: 用户账号是否处于活跃状态
        - is_superuser: 用户是否拥有超级管理员权限
        - is_verified: 用户账号是否已验证
        - 其他可能的自定义用户字段
        
        可能的错误：
        - 401 Unauthorized: 未提供访问令牌、令牌无效或已过期
        - 401 Unauthorized: 用户账号未激活
        
        使用场景：
        - 获取当前登录用户的个人资料
        - 验证用户的登录状态和权限
        """,
    )
    async def me(
        user: models.UP = Depends(get_current_active_user),
    ):
        return schemas.model_validate(user_schema, user)

    @router.patch(
        "/me",
        response_model=user_schema,
        dependencies=[Depends(get_current_active_user)],
        name="users:patch_current_user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS: {
                                "summary": "A user with this email already exists.",
                                "value": {
                                    "detail": ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS
                                },
                            },
                            ErrorCode.UPDATE_USER_INVALID_PASSWORD: {
                                "summary": "Password validation failed.",
                                "value": {
                                    "detail": {
                                        "code": ErrorCode.UPDATE_USER_INVALID_PASSWORD,
                                        "reason": "Password should be"
                                        "at least 3 characters",
                                    }
                                },
                            },
                        }
                    }
                },
            },
        },
        description="""
        更新当前认证用户的信息。
        
        此接口允许用户修改自己的个人资料，包括电子邮件地址和密码等信息。
        
        请求头要求：
        - Authorization: Bearer {access_token}，必须包含有效的访问令牌
        
        请求体（所有字段都是可选的）：
        - email: 新的电子邮件地址
        - password: 新的密码
        - is_active: 是否激活账号（通常用户不能修改此字段，仅在安全模式关闭时有效）
        - is_superuser: 是否为超级用户（通常用户不能修改此字段，仅在安全模式关闭时有效）
        - is_verified: 是否已验证（通常用户不能修改此字段，仅在安全模式关闭时有效）
        
        安全特性：
        - 此接口在安全模式下运行（safe=True），用户无法提升自己的权限
        - 用户只能修改允许的字段，如电子邮件和密码
        
        可能的错误：
        - 400 Bad Request: 新电子邮件地址已被其他用户使用
        - 400 Bad Request: 新密码不符合系统安全要求
        - 401 Unauthorized: 未提供访问令牌、令牌无效或已过期
        - 401 Unauthorized: 用户账号未激活
        
        返回：更新后的用户完整信息
        """,
    )
    async def update_me(
        request: Request,
        user_update: user_update_schema,  # type: ignore
        user: models.UP = Depends(get_current_active_user),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        try:
            user = await user_manager.update(
                user_update, user, safe=True, request=request
            )
            return schemas.model_validate(user_schema, user)
        except exceptions.InvalidPasswordException as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": ErrorCode.UPDATE_USER_INVALID_PASSWORD,
                    "reason": e.reason,
                },
            )
        except exceptions.UserAlreadyExists:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS,
            )

    @router.get(
        "/{id}",
        response_model=user_schema,
        dependencies=[Depends(get_current_superuser)],
        name="users:user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
            status.HTTP_403_FORBIDDEN: {
                "description": "Not a superuser.",
            },
            status.HTTP_404_NOT_FOUND: {
                "description": "The user does not exist.",
            },
        },
        description="""
        通过用户 ID 获取特定用户的详细信息。
        
        此接口允许超级管理员查看系统中任何用户的完整个人资料。
        
        请求头要求：
        - Authorization: Bearer {access_token}，必须包含有效的超级管理员访问令牌
        
        路径参数：
        - id: 目标用户的唯一标识符
        
        权限要求：
        - 调用者必须具有超级管理员权限（is_superuser=True）
        
        返回数据：
        - id: 用户唯一标识符
        - email: 用户电子邮件地址
        - is_active: 用户账号是否处于活跃状态
        - is_superuser: 用户是否拥有超级管理员权限
        - is_verified: 用户账号是否已验证
        - 其他可能的自定义用户字段
        
        可能的错误：
        - 401 Unauthorized: 未提供访问令牌、令牌无效或已过期
        - 403 Forbidden: 调用者不具备超级管理员权限
        - 404 Not Found: 指定 ID 的用户不存在
        
        使用场景：
        - 管理员查看特定用户的详细信息
        - 用户管理和审计
        """,
    )
    async def get_user(user=Depends(get_user_or_404)):
        return schemas.model_validate(user_schema, user)

    @router.patch(
        "/{id}",
        response_model=user_schema,
        dependencies=[Depends(get_current_superuser)],
        name="users:patch_user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
            status.HTTP_403_FORBIDDEN: {
                "description": "Not a superuser.",
            },
            status.HTTP_404_NOT_FOUND: {
                "description": "The user does not exist.",
            },
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS: {
                                "summary": "A user with this email already exists.",
                                "value": {
                                    "detail": ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS
                                },
                            },
                            ErrorCode.UPDATE_USER_INVALID_PASSWORD: {
                                "summary": "Password validation failed.",
                                "value": {
                                    "detail": {
                                        "code": ErrorCode.UPDATE_USER_INVALID_PASSWORD,
                                        "reason": "Password should be"
                                        "at least 3 characters",
                                    }
                                },
                            },
                        }
                    }
                },
            },
        },
        description="""
        通过用户 ID 更新特定用户的信息。
        
        此接口允许超级管理员修改系统中任何用户的个人资料和权限设置。
        
        请求头要求：
        - Authorization: Bearer {access_token}，必须包含有效的超级管理员访问令牌
        
        路径参数：
        - id: 目标用户的唯一标识符
        
        请求体（所有字段都是可选的）：
        - email: 新的电子邮件地址
        - password: 新的密码
        - is_active: 是否激活账号
        - is_superuser: 是否为超级用户
        - is_verified: 是否已验证
        
        权限要求：
        - 调用者必须具有超级管理员权限（is_superuser=True）
        
        安全特性：
        - 此接口在非安全模式下运行（safe=False），允许管理员修改所有用户字段
        - 管理员可以激活/停用用户账号，授予/撤销超级管理员权限
        
        可能的错误：
        - 400 Bad Request: 新电子邮件地址已被其他用户使用
        - 400 Bad Request: 新密码不符合系统安全要求
        - 401 Unauthorized: 未提供访问令牌、令牌无效或已过期
        - 403 Forbidden: 调用者不具备超级管理员权限
        - 404 Not Found: 指定 ID 的用户不存在
        
        返回：更新后的用户完整信息
        
        使用场景：
        - 管理员修改用户信息
        - 重置用户密码
        - 管理用户权限
        - 激活或停用用户账号
        """,
    )
    async def update_user(
        user_update: user_update_schema,  # type: ignore
        request: Request,
        user=Depends(get_user_or_404),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        try:
            # 将email设为None，确保不更新邮箱
            user_update_dict = user_update.dict(exclude_unset=True)
            if "email" in user_update_dict:
                user_update_dict.pop("email")
            user_update = user_update_schema(**user_update_dict)
            
            user = await user_manager.update(
                user_update, user, safe=False, request=request
            )
            return schemas.model_validate(user_schema, user)
        except exceptions.InvalidPasswordException as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": ErrorCode.UPDATE_USER_INVALID_PASSWORD,
                    "reason": e.reason,
                },
            )
        except exceptions.UserAlreadyExists:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS,
            )

    @router.delete(
        "/{id}",
        status_code=status.HTTP_204_NO_CONTENT,
        response_class=Response,
        dependencies=[Depends(get_current_superuser)],
        name="users:delete_user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
            status.HTTP_403_FORBIDDEN: {
                "description": "Not a superuser.",
            },
            status.HTTP_404_NOT_FOUND: {
                "description": "The user does not exist.",
            },
        },
        description="""
        通过用户 ID 删除特定用户。
        
        此接口允许超级管理员从系统中永久删除用户账号及其所有相关数据。
        
        请求头要求：
        - Authorization: Bearer {access_token}，必须包含有效的超级管理员访问令牌
        
        路径参数：
        - id: 目标用户的唯一标识符
        
        权限要求：
        - 调用者必须具有超级管理员权限（is_superuser=True）
        
        处理流程：
        1. 验证请求者具有超级管理员权限
        2. 检查指定 ID 的用户是否存在
        3. 从系统中永久删除用户及其相关数据
        
        可能的错误：
        - 401 Unauthorized: 未提供访问令牌、令牌无效或已过期
        - 403 Forbidden: 调用者不具备超级管理员权限
        - 404 Not Found: 指定 ID 的用户不存在
        
        返回：
        - 204 No Content，表示删除操作成功完成
        - 无响应体内容
        
        安全注意事项：
        - 此操作不可逆，删除后的用户数据无法恢复
        - 建议在执行删除操作前进行确认
        - 考虑实现软删除机制（将用户标记为非活跃而非物理删除）
        
        使用场景：
        - 移除不再需要的用户账号
        - 处理违反服务条款的账号
        - 数据清理和合规性要求
        """,
    )
    async def delete_user(
        request: Request,
        user=Depends(get_user_or_404),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        await user_manager.delete(user, request=request)
        return None

    return router
