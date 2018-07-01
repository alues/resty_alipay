--[[
    Alipay Client
]]

-- load comment libs
local http      = require("resty.http")

-- load private libs
local u_table          = require("alipay.utils.table")
local alipay_signature = require("alipay.utils.signature")

-- local func
local localtime    = ngx.localtime
local setmetatable = setmetatable

-- 
local _M = { _VERSION = '0.01.01' }

function _M.new(server_url, app_id, private_key, format, charset, alipay_public_key, sign_type)
--[[
    server_url: https://openapi.alipay.com/gateway.do
    app_id: 支付宝分配给开发者的应用ID
    private_key: 开发者设置的私钥 [PKCS8]
    format: 仅支持JSON
    charset: 请求使用的编码格式，如utf-8,gbk,gb2312等 *暂未实现对不同编码的处理*
    public_key: 支付宝公钥 [PKCS8]
    sign_type: 商户生成签名字符串所使用的签名算法类型，目前支持RSA2和RSA，推荐使用RSA2
]]
    local this = {}

    this.server_url = server_url
    this.app_id = app_id
    this.private_key = private_key
    this.format = format
    this.charset = charset
    this.public_key = alipay_public_key
    this.sign_type = sign_type
    return setmetatable(this, { __index = _M })
end

function _M:get_params(request)
--[[
    sign the params, and format the params
]]
    local params = {}

    params.app_id = self.app_id
    params.format = self.format
    params.charset = self.charset
    params.sign_type = self.sign_type
    params.timestamp = localtime()
    params.method = request.method
    params.version = request.version
    params.notify_url = request.notify_url
    params.biz_content = request.biz_content
    local sign_content = u_table.table2str_order(params)
    params.sign = alipay_signature.rsa_sign(sign_content, self.private_key, self.sign_type)
    return params
end

function _M:get_request_body(request)
    local params = self:get_params(request)
    for k, v in pairs(params) do
        params[k] = ngx.escape_uri(v)
    end
    return u_table.table2str(params)
end

function _M:execute(request)
--[[
    execute the query and return the result
]]
    local ret = { status = false }
    local req = http.new()
    local req_body = self:get_request_body(request)

    local res, err = req:request_uri(self.server_url, {
        method = "POST",
        body = req_body,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8",
        },
    })

    if not res then
        ngx.log(ngx.ERR, req_body, err)
        return ret
    end

    ret.status = true
    if res.status == 200 then
        ret.result = res.body
    elseif res.status == 302 then
        ret.result = res.headers.location
    end

    return ret
end

function _M:verify(sign_params)
--[[
    verify the sign of params without `sign_type`
]]
    sign_params.sign_type = nil
    local sign_content = u_table.table2str_order(sign_params)
    return alipay_signature.rsa_check(sign_content, sign_params.sign, self.public_key, self.sign_type)
end

return _M
