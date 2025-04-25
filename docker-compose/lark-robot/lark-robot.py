#!/usr/bin/env python3
#lark-robot.py

import os
import logging
import json
import uuid
from flask import Flask, request, jsonify
import lark_oapi as lark
from lark_oapi.api.im.v1 import CreateMessageRequest, CreateMessageRequestBody
from datetime import datetime, timedelta
import requests

# 创建 Flask 应用实例
app = Flask(__name__)

# 配置日志
logger = logging.getLogger('lark-robot')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# 存储已经处理过的 request_id
processed_request_ids = set()

# 处理所有请求的前置方法
@app.before_request
def handle_all_requests():
    path = request.path
    if path == '/url_verification' or path == '/lark-cicd':
        return None  # 让请求继续传递给相应的路由处理
    else:
        if 'X-Forwarded-For' in request.headers:
            ip = request.headers['X-Forwarded-For'].split(',')[0]
        else:
            ip = request.remote_addr
        return ip + "\n", 200, [("Server", "Go"), ("City", "Shanghai")]

# URL 验证接口
@app.route('/url_verification', methods=["POST"])
def url_verification():
    req = request.json
    if req.get("token") != VERIFICATION_TOKEN:
        raise Exception("VERIFICATION_TOKEN is invalid")
    return jsonify({"challenge": req.get("challenge")})

# 主业务逻辑接口
@app.route('/lark-cicd', methods=["POST"])
def index():
    req = request.json
    request_id = str(uuid.uuid4())
    # logger.info(f"Received request with ID: {request_id}, data: {req}")
    header = req.get("header", {})
    event_type = header.get("event_type")
    create_time = header.get("create_time")

    if req.get("type") == "url_verification":
        return url_verification()
    elif event_type == "im.message.receive_v1":
        event = req.get("event")
        message = event.get("message")
        group_id = message.get("chat_id")
        msg_content = json.loads(message.get("content")).get("text").split('@')[0]
        msg_content = msg_content.rstrip()

        # 检查 request_id 是否已经被处理过
        if request_id in processed_request_ids:
            logger.info(f"Request ID: {request_id} - Request already processed")
            return "succeed"
        else:
            processed_request_ids.add(request_id)  # 标记 request_id 为已处理
            if create_time: #检查消息是否在10秒以内
                try:
                    create_time_dt = datetime.fromtimestamp(int(create_time) / 1000)  # 转换为datetime对象
                    current_time_dt = datetime.now()
                    if current_time_dt - create_time_dt > timedelta(seconds=10):
                        logger.info(f"Request: {request_id} - {msg_content} - Message is too old")
                        return "succeed"
                except ValueError:
                    logger.error(f"Request ID: {request_id} - Invalid create_time format")
                    return "succeed"
            else:
                logger.error(f"Request ID: {request_id} - Missing create_time")
                return "succeed"

            if msg_content:  # 检查 msg_content 是否为空
                msg_name = next((mention.get("name") for mention in message.get("mentions", []) if mention.get("name")), None)
                logger.info(f"Msg: {msg_content} @{msg_name}")
                response_content = f"已收到 \n{msg_content}"
                # send_event_message(group_id, response_content)
                msg_cicd(group_id, msg_content)
                return "succeed"
            else:
                logger.warning(f"Request ID: {request_id} - message content is empty")
                return "succeed"
    else:
        logger.warning(f"Request ID: {request_id} - Unsupported event type: {event_type}")
        return "succeed"

# 发送消息到群聊
def send_event_message(group_id, response_content):
    client = lark.Client.builder() \
        .app_id(APP_ID) \
        .app_secret(APP_SECRET) \
        .domain(LARK_HOST) \
        .enable_set_token(True) \
        .log_level(lark.LogLevel.ERROR) \
        .build()

    request_body = CreateMessageRequestBody.builder() \
        .receive_id(group_id) \
        .msg_type("text") \
        .content(json.dumps({"text": response_content})) \
        .uuid(os.urandom(16).hex()) \
        .build()

    request = CreateMessageRequest.builder() \
        .receive_id_type("chat_id") \
        .request_body(request_body) \
        .build()

    response = client.im.v1.message.create(request)

    if not response.success():
        lark.logger.error(
            f"client.im.v1.message.create failed, code: {response.code}, msg: {response.msg}, log_id: {response.get_log_id()}, resp: \n{json.dumps(json.loads(response.raw.content), indent=4, ensure_ascii=False)}")
        return

    lark.logger.info(lark.JSON.marshal(response.data, indent=4))
    return "succeed"


##########
#cicd

#筛选消息，执行指令
def msg_cicd(group_id,text):
    msg = text
    #print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "msg->: ",  msg)
    
    #check group
    #test oc_492604c3bb7382afeb47448b726e0a7d
    if group_id != "oc_492604c3bb7382afeb47448b726e0a7d__":
        appInfoMap = dict(appProd, **appTest)
        myMenu = {"help", "prod", "test"}
        L = msg.split(" ")
        L = list(filter(lambda x: x != '', L))
        Len = len(L)
        if msg in appInfoMap:
            app_env = appInfoMap[msg][0]
            app_name = appInfoMap[msg][1]
            if msg.startswith("b"):
                app_url = appInfoMap[msg][2] + appInfoMap[msg][0]
            else:
                app_url = appInfoMap[msg][2]
                app_url = app_url + app_env + "&app_list=" + app_name
            if app_env != "":
                #执行通知
                msg = "env:  %s\napp  %s" % (app_env, app_name)
                send_event_message(group_id, msg)
                
                #向webhook发起post请求
                head = { 'User-Agent': "webhook-robot" }
                res = requests.post(url=app_url, headers=head)
                print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "webhook", app_env, app_name, res.reason)
                return "succeed"
            else:
                print(msg, "nothing")
                return "succeed"
        elif msg in myMenu:
            #打印命令列表
            print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "Send menu")
            msgTitle = "#命令  名称\n"
            if msg == "help":
                msgTitle2 = "#命令  获取列表\n"
                msg = msgTitle2 + "prod  app-prod-list\ntest  app-test-list"
            elif msg == "prod":
                msg = msgTitle
                for i in appProd:
                    msg = msg + i + "  " + appInfoMap[i][1] + "\n"
            elif msg == "test":
                msg = msgTitle
                for i in appTest:
                    msg = msg + i + "  " + appInfoMap[i][1] + "\n"
            msg = msg.rstrip('\n')
            send_event_message(group_id, msg)
            return "succeed"
        #多个app部署
        elif Len > 1:
            app = ""
            apps = ""
            app_env = ""
            for n in L:
                if n in appInfoMap:
                    app_name = appInfoMap[n][1]
                    app = app + app_name + " \n"
                    apps = apps + app_name + " "
                    app_env = appInfoMap[n][0]
                    app_url = appInfoMap[n][2]
            if app_env != "":
                #执行通知
                app = app.rstrip('\n')
                msg = f"env:  {app_env}\napp-list: \n{app}"
                send_event_message(group_id, msg)
                
                #向webhook发起post请求
                app_url = app_url + app_env + "&app_list=" + app
                head = { 'User-Agent': "webhook-robot" }
                res = requests.post(url=app_url, headers=head)
                print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "webhook", app_env, apps, res.reason)
                return "succeed"
            else:
                msg = f"已收到: \n{msg} \n发送 help@cici 查看支持指令"
                send_event_message(group_id, msg)
                return "succeed"
        else:
            msg = f"已收到: \n{msg} \n发送 help@cici 查看支持指令"
            send_event_message(group_id, msg)
            return "succeed"

    else:
        print("group_id no found",group_id)
        return "succeed"


# 从环境变量加载配置
APP_ID = os.getenv("APP_ID")
APP_SECRET = os.getenv("APP_SECRET")
VERIFICATION_TOKEN = os.getenv("VERIFICATION_TOKEN")
LARK_HOST = os.getenv("LARK_HOST", "https://open.larksuite.com")

##########
#cicd list

#webhook url for jenkins 
JenkinsBaseUrl = os.getenv("JenkinsBaseUrl")

#job
appDeploy = "test-app-deploy/buildWithParameters?token=cicdTest&app_branch=master&app_build=true&docker_build=true&create_git_tag=false&notice_msg=true&app_deploy=true&image_update=true&input_pass=true&deploy_tag=tag&deploy_env="

#ci url
appDeployUrl = JenkinsBaseUrl + appDeploy

appProd = {
"#app-prod-k8s-list:": ["","", ""],
"s101": ["prod","app-web", appDeployUrl],
"s102": ["prod","app-svc", appDeployUrl],
"s103": ["prod","app-api", appDeployUrl],
"s104": ["prod","app-event", appDeployUrl],
"s105": ["prod","app-admin", appDeployUrl],
}

appTest = {
"#app-test-k8s-list:": ["","", ""],
"s201": ["test","app-web", appDeployUrl],
"s202": ["test","app-svc", appDeployUrl],
"s203": ["test","app-api", appDeployUrl],
"s204": ["test","app-event", appDeployUrl],
"s205": ["test","app-admin", appDeployUrl],
}

##########

# 启动 Flask 应用
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8092, debug=False)
