from typing import List
from django.shortcuts import get_object_or_404
import jwt
from django.http import JsonResponse, request
from django.core.exceptions import ObjectDoesNotExist
from backend.settings import SECRET_KEY
from account.models import Account, Profile

# 토큰 체크 함수
def tokenCheckDecorator(func):
    def wrapper(request, *args, **kwargs):
        try:
            token = request.COOKIES["token"]
        except:
            return JsonResponse("토큰값이 없습니다", status=400, safe=False)
        try:
            token = jwt.decode(token, SECRET_KEY, algorithms="HS256")
            account = Account.objects.get(email=token["email"])
            request.account = account
        except jwt.exeptions.DecodeError:
            return JsonResponse('유효하지 않은 토큰', status=401)
        except Account.DoesNotExist:
            return JsonResponse('해당 유저가 없습니다', status=404)
        # 프로필 탐색
        try:
            profile = Profile.objects.get(account=account)
            request.profile = profile
        except Profile.DoesNotExist:
            return JsonResponse("해당 유저가 프로필을 생성하지 않았습니다", status=404)
        return func(request, *args, **kwargs)
    return wrapper

# 프로필 탐색 없는 토큰 체크 함수
def tokenCheckWithOutProfileDecorator(func):
    def wrapper(request, *args, **kwargs):
        try:
            token = request.COOKIES["token"]
        except:
            return JsonResponse("토큰값이 없습니다", status=400, safe=False)
        try:
            token = jwt.decode(token, SECRET_KEY, algorithms="HS256")
            account = Account.objects.get(email=token["email"])
            request.account = account
        except jwt.exeptions.DecodeError:
            return JsonResponse('유효하지 않은 토큰', status=401)
        except Account.DoesNotExist:
            return JsonResponse('해당 유저가 없습니다', status=404)
        
        return func(request, *args, **kwargs)
    return wrapper    

# 유효성 체크 함수
def validiationCheck(requiredList:List, requestKeysList:List):

    requiredListSet = set(requiredList)
    requestKeysListSet = set(requestKeysList)

    requestCheck = requiredListSet- requestKeysListSet

    return requestCheck == set([]) and True or False