-- HTTP authentication using REST-like json based API authentication
-- e.g. node.js passport local strategy
--
-- author: Sebastian Castillo <castillobuiles@gmail.com>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

local log = require "util.logger".init("auth_json_http");
local ltn12 = require "ltn12";
local util_sasl_new = require "util.sasl".new;

-- authentication = "json_http"
-- auth_json_http_url = "http://192.168.50.1:3000/api/v1/auth/local"
local auth_url = module:get_option_string("auth_json_http_url", "http://127.0.0.1/api/v1/auth/local");
log("debug", "auth_url: %s", auth_url);
assert(auth_url, "HTTP URL is needed");


-- for 0.9
provider = {};
--provider = {
--    name = module.name:gsub("^auth_","");
--};
-- globals required by socket.http
if rawget(_G, "PROXY") == nil then
    rawset(_G, "PROXY", false)
end
if rawget(_G, "base_parsed") == nil then
    rawset(_G, "base_parsed", false)
end
local have_async = false;
if not have_async then -- FINE! Set your globals then
    prosody.unlock_globals()
    require "ltn12"
    require "socket"
    require "socket.http"
    require "ssl.https"
    prosody.lock_globals()
end


local function getPassword(username)
    module:log("debug", "getPassword ?", username);
    require "ltn12";
    local http = require "socket.http";
    local https = require "ssl.https";
    local json = require "util.json";

    local request = json:encode({ userId = username });
    local responBody = {};
    local httpRequest;
    if string.sub(auth_url, 1, string.len('https')) == 'https' then
        httpRequest = https.request;
    else
        httpRequest = http.request;
    end

    local resultObject, responCode, responHeader, responStatus = httpRequest{
        method = "POST",
        url = auth_url + "/get-password",
        headers {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = tostring(#request)
        },
        source = ltn12.source.string(request),
        sink = ltn12.sink.table(responBody)
    };

    log("debug", "resultObject "..resultObject)
    log("debug", "responseCode "..responCode)

    if respcode == 200 then
        local responseObject = json.decode(responBody);
        if resultObject.status == true then
            return responseObject.userId;
        else
            return ""
        end
    else
        return "";
    end

end

function provider.get_sasl_handler()
    local getpass_authentication_profile = {
        plain_test = function(sasl, username, password, realm)
            module:log("debug", "get_sasl_handler().getpass_authentication_profile %s", username..":"..password);
            require "ltn12";
            local http = require "socket.http";
            local https = require "ssl.https";
            local json = require "util.json";

            local credentials = json.encode({ userId = string.upper(username), userPassword = string.upper(password), sessionId="",conferenceId="",roomName="",status="true",message="",userIdRequest="" });
            local respbody = {};
            local httpRequest;
            if string.sub(auth_url, 1, string.len('https')) == 'https' then
                httpRequest = https.request;
            else
                httpRequest = http.request;
            end
            local result, respcode, respheaders, respstatus = httpRequest{
                method = "POST",
                url = auth_url.."/user-login",
                headers = {
                    ["Content-Type"] = "application/json",
                    ["Content-Length"] = tostring(#credentials)
                },
                source = ltn12.source.string(credentials),
                sink = ltn12.sink.table(respbody)
            }
            log("debug", "get_sasl_handler().respcode: %s", respcode);
            log("debug", "get_sasl_handler().result: %s", result);

            if respcode == 200 then
                log("debug", "JSON result "..result);
                local resultObject = json.decode(result);
                if resultObject.status == true then
                    return true, true;
                else
                    return false, true;
                end
            else
                return false, true;
            end

            -- return respcode == 200, true;
        end,
    };
    return util_sasl_new(module.host, getpass_authentication_profile);
end

-- Non implemented

function provider.create_user(username, password)
    log("debug", "create_user() not implemented");
    return nil, "Not implemented"
end

function provider.delete_user(username)
    log("debug", "delete_user() not implemented");
    return nil, "Not implemented"
end

function provider.set_password(username, password)
    log("debug", "set_password() not implemented");
    return nil, "Not implemented"
end

function provider.test_password(username, password)
    log("debug", "test_password() not implemented");
    return password and getPassword(username) == password;
end

function provider.get_password(username)
    log("debug", "get_password() not implemented")
    return getPassword(username);
end

function provider.user_exists(username)
    log("debug", "user_exist() not implemented")
    return getPassword(username) and true;
end
function provider.users()
    return function()
        return nil;
    end
end

-- module:add_item("auth-provider", provider);
-- for 0.9
module:provides("auth", provider)