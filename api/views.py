import re

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.serializers import jwt_encode_handler
from rest_framework_jwt.serializers import jwt_payload_handler

from api.models import User
from api.serializers import UserModelSerializer
from utils.response import APIResponse
from api.authentication import JWTAuthentication


class UserDetailAPIView(APIView):

    permission_classes = [IsAuthenticated]
    # authentication_classes = [JSONWebTokenAuthentication]
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        return APIResponse(results={"username": request.user.username})


class LoginAPIView(APIView):


    authentication_classes = []
    permission_classes = []

    def post(self, request, *args, **kwargs):

        user_ser = UserModelSerializer(data=request.data)
        user_ser.is_valid(raise_exception=True)

        return APIResponse(data_message="ok", token=user_ser.token, results=UserModelSerializer(user_ser.obj).data)


    def demo_post(self, request, *args, **kwargs):
        account = request.data.get("account")
        pwd = request.data.get("pwd")

        # 对于各种登录方式做处理  账号  邮箱  手机号
        if re.match(r'.+@.+', account):
            user_obj = User.objects.filter(email=account).first()
        elif re.match(r'1[3-9][0-9]{9}', account):
            user_obj = User.objects.filter(phone=account).first()
        else:
            user_obj = User.objects.filter(username=account).first()


        if user_obj and user_obj.check_password(pwd):

            payload = jwt_payload_handler(user_obj)  # 生成载荷信息
            token = jwt_encode_handler(payload)  # 生成token
            return APIResponse(results={"username": user_obj.username}, token=token)

        return APIResponse(data_message="错误了")
