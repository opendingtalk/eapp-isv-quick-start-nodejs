var crypto = require('crypto');
var httpReq = require('./libs/http');
var DDCrypto = require('./libs/ddcrypto');

var express = require('express');
var path = require('path');
var fs = require('fs');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var app = express();

var config = require('./config.default.js');
var Cipher = new DDCrypto(config.token, config.encodingAESKey, config.suiteKey);

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(cookieParser());

HttpUtils = new httpReq(config.oapiHost);

// 获取用户信息
app.use('/login', function(req, res) {
    var code = req.body.authCode;
    var corpId = req.body.corpId;

    // 时间戳
    var timeStamp = new Date().getTime();
    // 正式应用应该由钉钉通过开发者的回调地址动态获取到
    var suiteTicket = getSuiteTicket(config.suiteKey);
    // 构造/service/get_corp_token接口的消息体
    var msg = timeStamp + "\n" + suiteTicket;
    // 把timestamp+"\n"+suiteTicket当做签名字符串，suiteSecret做为签名秘钥，使用HmacSHA256算法计算签名，然后进行Base64 encode获取最后结果。然后把签名参数再进行urlconde，加到请求url后面
    var sha = encodeURIComponent(crypto.createHmac('SHA256', config.suiteSecret).update(msg).digest('base64'));
    // 调用接口获取access_token
    HttpUtils.post("/service/get_corp_token", {
        "accessKey": config.suiteKey,
        "timestamp": timeStamp,
        "suiteTicket": suiteTicket,
        "signature": sha,
    }, {
        "auth_corpid": corpId,
    }, function(err, body) {
        var accessToken = body.access_token; 
        HttpUtils.get("/user/getuserinfo", {
            "access_token": accessToken,
            "code": code,
        }, function(err, body) {
            res.send({
                result: {
                    userId: body.userid,
                }
            });
        });
    });

});

// 验证回调
app.use('/receive', function(req, res) {
    var body = req.body;
    if (!body || !body.encrypt) {
        return;
    }
    var encrypt = body.encrypt;

    //解密推送信息
    var data = Cipher.decrypt(encrypt);
    //解析数据结构
    var json = JSON.parse(data.message) || {};
    var msg = '';
    //处理不同类型的推送数据
    switch (json.EventType) {
        // 验证新创建的回调URL有效性
        case 'check_create_suite_url':
            msg = 'success';
            break;
        // 验证更新回调URL有效性
        case 'check_update_suite_url':
            msg = 'success';
            break;
        // 应用suite_ticket数据推送
        //suite_ticket用于用签名形式生成accessToken(访问钉钉服务端的凭证)，需要保存到应用的db。
        //钉钉会定期向本callback url推送suite_ticket新值用以提升安全性。
        //应用在获取到新的时值时，保存db成功后，返回给钉钉success加密串（如本demo的return）
        case 'suite_ticket':
            msg = 'success';
            break;
        // 企业授权开通应用事件
        //本事件应用应该异步进行授权开通企业的初始化，目的是尽最大努力快速返回给钉钉服务端。用以提升企业管理员开通应用体验
        //即使本接口没有收到数据或者收到事件后处理初始化失败都可以后续再用户试用应用时从前端获取到corpId并拉取授权企业信息，
        // 进而初始化开通及企业。
        case 'tmp_auth_code':
            msg = 'success';
            break;
        default:
            // 其他类型事件处理
    }
    //加密文本
    var text = Cipher.encrypt(msg);
    //生成随机串
    var stmp = Date.now();
    //生成随机数
    var nonce = Math.random().toString(36).substring(2);

    //签名文本
    var sign = Cipher.getSignature(stmp, nonce, text);

    //返回给推送服务器的信息
    var result = {
        msg_signature: sign,
        timeStamp: stmp,
        nonce: nonce,
        encrypt: text
    };
    
    res.send(result);
});

app.use(function(req, res, next) {
  res.send('welcome')
});

function getSuiteTicket() {
    return "temp_suite_ticket_only4_test";
}
module.exports = app;