from django.http import HttpResponse, JsonResponse
from django.forms.models import model_to_dict
from django.shortcuts import get_object_or_404
from .models import Account, Profile
import json
from django.utils import timezone
from django.core import serializers
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views import View
import bcrypt
import jwt
from backend.settings import SECRET_KEY
from core.utils import tokenCheckDecorator,validiationCheck,tokenCheckNonProDecorator
# Create your views here.

# 로그인
@csrf_exempt
def signIn(request):
    try:
        requestData = json.load(request)
    except:
        return JsonResponse("규격에 맞는 데이터를 넣어주세요", safe=False, status=400)
    accountCheck = Account.objects.filter(email=requestData["email"])

    if request.method == "POST":
        if accountCheck.exists():
            account = Account.objects.get(email=requestData["email"])
            if bcrypt.checkpw(requestData["password"].encode('utf-8'), account.password.encode('utf-8')):
                token = jwt.encode({'email': account.email, 'exp': timezone.now(
                )+timezone.timedelta(days=7)}, SECRET_KEY, algorithm="HS256")
                result = JsonResponse(model_to_dict(
                    account, fields=("email")), safe=False)
                result.set_cookie('token', token)
                return result

            return JsonResponse('비밀번호가 일치하지 않습니다', safe=False, status=400)

        return JsonResponse('아이디나 비밀번호가 일치하지 않습니다', safe=False, status=404)
    else:
        return JsonResponse("허용하지 않는 요청 메서드 입니다", status=405, safe=False )

# 회원가입
@csrf_exempt
def signUp(request):
    try:
        requestData = json.load(request)
    except:
        return JsonResponse("규격에 맞는 데이터를 넣어주세요", safe=False, status=400)
    accountCheck = Account.objects.filter(email=requestData["email"])

    if request.method == "POST":
        if accountCheck.exists():
            return JsonResponse('이미 가입 이력이 존재합니다', safe=False, status=400)
        password = requestData["password"].encode('utf-8')
        passwordCrypt = bcrypt.hashpw(password, bcrypt.gensalt())
        passwordCrypt = passwordCrypt.decode('utf-8')
        newAccount = Account(
            email=requestData["email"], password=passwordCrypt)
        newAccount.save()
        token = jwt.encode({'email': newAccount.email, 'exp': timezone.now()+timezone.timedelta(days=7)},
                           SECRET_KEY, algorithm="HS256")
        result = JsonResponse(model_to_dict(
            newAccount, fields=('email')), safe=False)
        result.set_cookie('token', token)
        return result

@csrf_exempt
@tokenCheckNonProDecorator

def index(request):
    try:
        requestData = json.load(request)
    except:
        return JsonResponse("규격에 맞는 데이터를 넣어주세요", safe=False, status=400)
    
    account = request.account

    # 회원 정보 조회
    if request.method == "GET":
        
        result = JsonResponse(model_to_dict(
                    account, fields=("email")), safe=False)
        return result

    # 회원 정보 수정 (password)
    # 미완성
    if request.method == "PATCH":
        validCheck = validiationCheck(["password"], requestData.keys())
        if validCheck == False:
            return JsonResponse("규격에 맞는 데이터를 넣어주세요", safe=False, status=400)

        password = requestData["password"].encode('utf-8')
        passwordCrypt = bcrypt.hashpw(password, bcrypt.gensalt())
        passwordCrypt = passwordCrypt.decode('utf-8')
        account.password=passwordCrypt
        account.save()

        return JsonResponse("비밀번호 변경 완료",safe=False)

    # 회원탈퇴
    # 미완성
    if request.method == "DELETE":
        account.delete()
        return JsonResponse("계정 삭제 완료", safe=False)

# token 체크
@csrf_exempt
def tokenCheck(request):
    try:
        token = request.COOKIES["token"]
    except:
        JsonResponse("토큰 값이 없습니다", safe=False, status=401)
    userTokenInfo = jwt.decode(token, SECRET_KEY, algorithms="HS256")
    result = None
    if Account.objects.filter(email=userTokenInfo["email"]).exists():
        result = JsonResponse("검증된 사용자", safe=False,status=202)
        return result
    result = JsonResponse("검증되지 않은 사용자", safe=False, status=401)
    result.delete_cookie('token')
    return result


# 프로필 관리
@csrf_exempt
@tokenCheckDecorator
def profile(request):
    account = request.account
    try:
        requestData = json.load(request)
    except:
        return JsonResponse("규격에 맞는 데이터를 넣어주세요", safe=False, status=400)

    # 프로필 읽기
    if request.method == "GET":
        try:
            accountProfile = get_object_or_404(Profile, account=account)
            result = model_to_dict(accountProfile)
            jsonResult = JsonResponse(result, safe=False)
            return jsonResult
        except Profile.DoesNotExist:
            return JsonResponse("프로필이 존재하지 않습니다", status=404)
    
    # 프로필 생성
    if request.method == "POST":
        profileCheck = Profile.objects.filter(account=account)
        if profileCheck.exists():
            return JsonResponse("이미 프로필이 존재합니다", safe=False, status=400)
        newProfile = Profile(username=requestData["username"], phoneNumber=int(
            requestData["phoneNumber"]), male=requestData["male"], birthday=requestData["birthday"], latitude=requestData["latitude"], longitude=requestData["longitude"],
            account=account)
        newProfile.save()
        newProfile = model_to_dict(newProfile)
        result = JsonResponse(newProfile, safe=False)
        return result

    # 프로필 수정
    # 미완성
    if request.method == "PATCH":
        accountProfile = get_object_or_404(Profile, account=account)
        requestKey = requestData.keys()
        if not requestKey:
            return JsonResponse("request 객체가 비었습니다", safe=False, status=400)
        return JsonResponse("request 확인", safe=False)

    # 프로필 삭제
    # 미완성    
    if request.method == "DELETE":
        return request
