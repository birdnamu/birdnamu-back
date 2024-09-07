# sewana/custom_exception_handler.py
from rest_framework.views import exception_handler
from django.http import JsonResponse

''' get_response 함수의 역할:  인자들을 받아서 양식에 맞춰 반환하는 기능'''
def get_response(message="", result={}, status=False, status_code=200):
  return {
    "message": message,
    "result": result,
    "status": status,
    "status_code": status_code
  }

''' get_error_message 함수 & handle_exception 함수의 역할:
원래 응답을 잘 파싱하여, 우리가 원라는 정보(상태값, 에러 메세지 들)를 가공해 내는 작업을 합니다.
parse, parsing => 데이터를 잘라낸다는 의미
'''
def get_error_message(error_dict):
  field = next(iter(error_dict))
  response = error_dict[next(iter(error_dict))]
  if isinstance(response, dict):
    response = get_error_message(response)
  elif isinstance(response, list):
    response_message = response[0]
    if isinstance(response_message, dict):
      response = get_error_message(response_message)
    else:
      response = response[0]
  return response

def handle_exception(exc, context):
  error_response = exception_handler(exc, context)
  if error_response is not None:
    error = error_response.data
    
    if isinstance(error, list) and error:
      if isinstance(error[0], dict):
        error_response.data = get_response(
          message=get_error_message(error),
          status_code=error_response.status_code
          )
      elif isinstance(error[0], str):
        error_response.data = get_response(
          message=error[0],
          status_code=error_response.status_code
          )
    if isinstance(error, dict):
      error_response.data = get_response(
        message=get_error_message(error),
        status_code=error_response.status_code
      )
  return error_response

''' ExceptionMiddleware : 직접 만든 미들웨어!!
우리 프로젝트에서 어떠한 에러사항에 대한 응답을 처리할 때,
미들웨어를 통해서, 우리가 만든 함수들을 활용하여 처리할 수 있다. 
'''
class ExceptionMiddleware(object):
  def __init__(self, get_response):
    self.get_response = get_response
  
  def __call__(self, request):
    response = self.get_response(request)
    if response.status_code == 500:
      response = get_response(
        message="Internal server error, please try again later",
        status_code=response.status_code
      )
      return JsonResponse(response, status=response['status_code'])
    
    if response.status_code == 404 and "Page not found" in str(response.content):
      response = get_response(
        message="Page not found, invalid url",
        status_code=response.status_code
      )
      return JsonResponse(response, status=response['status_code'])
    
    return response