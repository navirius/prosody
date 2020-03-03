local saslprep = require "util.encodings".stringprep.saslprep;
local log = require "util.logger".init("external");
local _ENV = nil;
-- luacheck: std none

local function external(self, message)
    log("debug", "external().message "..message);
    message = saslprep(message);
    local state
    self.username, state = self.profile.external(self, message);

    if state == false then
        return "failure", "account-disabled";
    elseif state == nil  then
        return "failure", "not-authorized";
    elseif state == "expired" then
        return "false", "credentials-expired";
    end

    return "success";
end

local function init(registerMechanism)
    registerMechanism("EXTERNAL", {"external"}, external);
end

return {
    init = init;
}
