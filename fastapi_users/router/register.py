from fastapi import APIRouter, Depends, HTTPException, Request, status

from fastapi_users import exceptions, models, schemas
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.router.common import ErrorCode, ErrorModel


def get_register_router(
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    user_schema: type[schemas.U],
    user_create_schema: type[schemas.UC],
) -> APIRouter:
    """Generate a router with the register route."""
    router = APIRouter()

    @router.post(
        "/register",
        response_model=user_schema,
        status_code=status.HTTP_201_CREATED,
        name="register:register",
        description="""
        注册新用户。
        
        此接口允许创建新用户账号，需要提供用户基本信息，包括电子邮件和密码。
        
        请求体应包含：
        - email: 有效的电子邮件地址（必填）
        - password: 用户密码（必填）
        - is_active: 是否激活账号（可选，默认为True）
        - is_superuser: 是否为超级用户（可选，默认为False）
        - is_verified: 是否已验证（可选，默认为False）
        
        成功注册后返回创建的用户信息（不包含密码）。
        
        注意：在API测试环境中，可以通过设置is_superuser=True来注册管理员账号，以便测试需要管理员权限的接口。
        在生产环境中应当限制此权限。
        """,
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            ErrorCode.REGISTER_USER_ALREADY_EXISTS: {
                                "summary": "A user with this email already exists.",
                                "value": {
                                    "detail": ErrorCode.REGISTER_USER_ALREADY_EXISTS
                                },
                            },
                            ErrorCode.REGISTER_INVALID_PASSWORD: {
                                "summary": "Password validation failed.",
                                "value": {
                                    "detail": {
                                        "code": ErrorCode.REGISTER_INVALID_PASSWORD,
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
    )
    async def register(
        request: Request,
        user_create: user_create_schema,  # type: ignore
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        try:
            created_user = await user_manager.create(
                user_create, safe=False, request=request
            )
        except exceptions.UserAlreadyExists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.REGISTER_USER_ALREADY_EXISTS,
            )
        except exceptions.InvalidPasswordException as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": ErrorCode.REGISTER_INVALID_PASSWORD,
                    "reason": e.reason,
                },
            )

        return schemas.model_validate(user_schema, created_user)

    return router
