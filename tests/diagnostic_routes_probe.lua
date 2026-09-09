-- Invoked by the Python wrapper after pin verification. Guest code receives
-- no host file/process/network access, package loader or debug facilities.
local sources = {}
for i = 1, 2 do
    local f = assert(io.open(assert(arg[i]), 'rb'))
    sources[i] = f:read('*all')
    f:close()
end
local checks = {}
local function bounded(fn)
    local ticks = 0
    debug.sethook(function()
        ticks = ticks + 1
        assert(ticks < 200, 'Guest instruction budget exceeded')
    end, '', 1000)
    local ok, value = pcall(fn)
    debug.sethook()
    assert(ok, value)
    return value
end
local function run(source, env)
    return bounded(function() return setfenv(assert(loadstring(source, 'pinned-guest')), env)() end)
end
local function record(name, fields)
    fields.name = name
    checks[#checks+1] = fields
end

for _, status in ipairs({0, 256}) do
    local callback, calls = nil, 0
    local env = {
        print=function() end,
        require=function(name)
            assert(name == 'mcd')
            return {notify=function(rule, fn)
                assert(rule == 'ACPClient_ON' and not callback)
                callback = fn
            end}
        end,
        os={execute=function(command)
            assert(command == '/bin/sh /boot/scripts/runacpclient.sh & ')
            calls = calls + 1
            return status
        end},
    }
    run(sources[1], env)
    assert(callback and calls == 0)
    bounded(callback)
    assert(calls == 1)
    -- The external shell script's lock is not simulated here. The Lua callback
    -- requests launch again even when the first mocked execute returned failure.
    bounded(callback)
    assert(calls == 2)
    record('insight_launch_status_'..status, {launch_requests=calls, host_commands=0})
end

local function apple(name, options)
    local opens, sleeps, sets, emits, conversions = 0, 0, 0, 0, 0
    local mount = '/synthetic/ipod7'
    local xml = {info={device={transport={usb={product='SyntheticPhone', manufacturer='SyntheticVendor'}},
                              authcoproc={device=3, protocol='2.00', private_test_marker='NOT_FORWARDED'}}}}
    local utils = {ConnMgrBusName='synthetic.ConnMgr', ConvertXml=function(data)
        assert(data == 'SYNTHETIC_XML')
        conversions = conversions + 1
        if options.bad_xml then return nil end
        return xml
    end}
    local service = {invoke=function(bus, method, params)
        assert(bus == utils.ConnMgrBusName and params.guid == 'synthetic-guid')
        if method == 'setProperties' then
            sets = sets + 1
            assert(params.set.dev.product_str == 'SyntheticPhone')
            assert(params.set.dev.vendor_str == 'SyntheticVendor')
            for key in pairs(params.set.dev) do
                assert(key == 'product_str' or key == 'vendor_str', 'Unexpected forwarded metadata')
            end
            for key in pairs(params.set) do assert(key == 'dev') end
        elseif method == 'emitProxy' then
            emits = emits + 1
            assert(params.name == 'inserted')
        else error('Unexpected guest service method: '..method) end
        return {}
    end}
    local log = {error=function() end, notice=function() end, info=function() end}
    local env = {
        arg={[0]='stock-AppleAppIns', 'synthetic-guid', '/synthetic/session'},
        string={format=string.format}, print=function() end,
        require=function(module)
            if module == 'connmgr.Utils' then return utils end
            if module == 'connmgr.Print' then return log end
            if module == 'service' then return service end
            assert(module == 'json', 'Unexpected guest module')
            return {decode=function(data) assert(data == 'SYNTHETIC_SESSION'); return {false, false, mount} end}
        end,
        os={sleep=function(seconds) assert(seconds == 1); sleeps = sleeps + 1 end},
        io={open=function(path, mode)
            assert(mode == nil or mode == 'r', 'Guest file write forbidden')
            local data
            if path == '/synthetic/session' then
                if options.no_session then return nil end
                data = 'SYNTHETIC_SESSION'
            else
                assert(path == mount..'/.FS_info./info.xml', 'Unexpected guest file')
                opens = opens + 1
                if options.no_info or opens <= (options.fail_opens or 0) then return nil end
                data = 'SYNTHETIC_XML'
            end
            return {read=function(_, format) assert(format == '*a'); return data end, close=function() end}
        end},
    }
    run(sources[2], env)
    local usable = not (options.no_session or options.no_info or options.bad_xml)
    assert(sets == (usable and 1 or 0))
    assert(emits == (options.no_session and 0 or 1))
    assert(opens == (options.no_session and 0 or options.no_info and 5 or 1+(options.fail_opens or 0)))
    assert(sleeps == (options.no_info and 5 or options.fail_opens or 0))
    record(name, {info_open_attempts=opens, virtual_sleeps=sleeps, property_updates=sets,
                  inserted_signals=emits, xml_conversions=conversions, auth_fields_forwarded=false})
end
apple('apple_consumer_discards_auth_fields', {})
apple('apple_consumer_retries', {fail_opens=2})
apple('apple_consumer_no_info', {no_info=true})
apple('apple_consumer_bad_xml', {bad_xml=true})
apple('apple_consumer_no_session', {no_session=true})

local function json(value)
    if type(value) == 'string' then
        return '"'..value:gsub('[%z\1-\31\\"]', function(c)
            return string.format('\\u%04x', string.byte(c))
        end)..'"'
    end
    if type(value) == 'number' or type(value) == 'boolean' then return tostring(value) end
    assert(type(value) == 'table')
    local out = {}
    if #value > 0 then
        for _, v in ipairs(value) do out[#out+1] = json(v) end
        return '['..table.concat(out, ',')..']'
    end
    local keys = {}
    for k in pairs(value) do keys[#keys+1] = k end
    table.sort(keys)
    for _, k in ipairs(keys) do out[#out+1] = json(k)..':'..json(value[k]) end
    return '{'..table.concat(out, ',')..'}'
end
print(json(checks))
