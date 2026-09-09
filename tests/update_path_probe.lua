-- Run via scripts/probe_update_path.py, which verifies every vendor input.
-- Host Lua 5.1.5 must use 32-bit size_t to read the original QNX bytecode.
-- Only this harness can access host files/debug; none are exposed to guests.
local sources = {}
for i = 1, 5 do
    local f = assert(io.open(assert(arg[i]), 'rb'))
    sources[i] = f:read('*all')
    f:close()
end
local results = {}
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
    return setfenv(assert(loadstring(source, 'pinned-guest')), env)()
end
local function stream(lines, value, close_status)
    return {
        lines = function()
            local i = 0
            return function() i = i + 1; return lines[i] end
        end,
        read = function(_, mode) assert(mode == '*all'); return value end,
        close = function() return close_status or 0 end,
    }
end
local function base()
    -- No host fallback metatable, package loader, debug, or file access.
    return {assert=assert, ipairs=ipairs, pairs=pairs, pcall=pcall, type=type,
        tonumber=tonumber, tostring=tostring, string=string, table=table,
        print=function() end}
end
local swdl = bounded(function() return run(sources[1], {}) end)
local install = bounded(function() return run(sources[2], {}) end)
assert(swdl.version == '6.17.0WL' and #swdl.parts == 0)
assert(install.version == '6.17.0WL' and #install.parts == 7)
local nav_script = 'usr/share/scripts/nav-activation/nav-activation-install.sh'
local app_script = 'usr/share/scripts/app-install/eu-app-install.sh'
assert(install.external.start_script == nav_script)
local expected = {'ifs', 'mmc', 'cleanup', 'cleanup', 'etfs', 'nav-sync', 'mmc'}
for i, part in ipairs(install.parts) do assert(part.installer == expected[i]) end

local function resident(options)
    local trace = {events={}, fast_checks=0, full_checks=0, sam_checks=0,
        manifests=0, external_calls=0, mounts=0}
    local function event(text) trace.events[#trace.events+1] = text end
    local callbacks, methods = {}, nil
    local mock_service = {
        register=function(name, value)
            assert(name == 'com.harman.service.SoftwareInstaller')
            methods = value
            return 'mock-service'
        end,
        unregister=function(id) assert(id == 'mock-service') end,
        emit=function(id, signal, params)
            assert(id == 'mock-service' and signal == 'updateStatus')
            event('status:'..params.state)
            if params.errorInfo then trace.error = params.errorInfo.name end
        end,
        invoke=function(name, method, params)
            assert(name == 'com.harman.service.samSecurity')
            assert(method == 'verifySignature' and params.signType == 'appUpdate')
            trace.sam_checks = trace.sam_checks + 1
            event('sam:'..(options.sam_ok and 'Success' or 'Failure'))
            return {result=options.sam_ok and 'Success' or 'Failure'}
        end,
    }
    local mock_os = {
        execute=function(cmd)
            if cmd == '/usr/bin/verifyISO sha256 /fs/usb0/swdl.iso' then
                trace.full_checks = trace.full_checks + 1
                event('full_verifier:'..tostring(options.full_status or 0))
                return options.full_status or 0
            end
            if cmd == '/fs/swdl/'..nav_script or cmd == '/fs/swdl/'..app_script then
                trace.external_calls = trace.external_calls + 1
                trace.external_script = cmd
                event('external_script_intercepted')
                return 256 -- Simulate immediate failure, without running a shell.
            end
            if cmd:match('^inject %-e %-i /fs/usb0/swdl') or
               cmd:match('^isodigest %-df /tmp/iso.digest /fs/usb0/swdl') or
               cmd:match('^rm %-f /tmp/') or
               cmd == 'openssl base64 -in /tmp/isoHash.sign -out /tmp/isoHash.sign.64' then
                return 0
            end
            error('Unexpected guest command: '..cmd)
        end,
        mount=function(path, destination, mode, fs, flags)
            local expected_iso = options.pair and 'swdlInstall.iso' or 'swdl.iso'
            assert(path == '/fs/usb0/'..expected_iso)
            assert(destination == '/fs/swdl' and mode == 'r' and fs == 'cd' and flags == 'exe')
            trace.mounts = trace.mounts + 1
            event('mount:'..expected_iso)
            if options.mount_fail then return nil, 'mock mount failure' end
            return true
        end,
        umount=function(path) assert(path == '/fs/swdl'); event('unmount') end,
        setenv=function(name, value)
            assert((name == 'ISO_PATH' and value == '/fs/swdl') or
                   (name == 'USB_PATH' and value == '/fs/usb0'))
        end,
    }
    local mock_io = {
        popen=function(cmd, mode)
            assert(mode == 'r')
            if cmd:match('^openssl dgst %-sha256 %-verify /etc/keys/apps.pub ') then
                trace.fast_checks = trace.fast_checks + 1
                local accepted = options.fail_fast ~= trace.fast_checks
                event('fast_signature:'..(accepted and 'accepted' or 'rejected'))
                return stream({accepted and 'Verified OK' or 'Verification failure'})
            end
            assert(cmd:match('^hashFile sha256 /fs/usb0/swdlInstall.iso '), cmd)
            event('payload_hash_mocked')
            return stream({})
        end,
        open=function(path, mode)
            assert(mode == 'r')
            if path == '/etc/version.txt' then
                return stream({'version=6.9.0WL'})
            end
            if path == '/tmp/isoHash.sign.64' then return stream({}, 'MOCK_METADATA\n') end
            if path == '/tmp/isoHash.sha256' then return stream({}, string.rep('A',32)) end
            if path == '/tmp/isoHash.sign' then
                -- Deliberately different mock hash bytes; no real signed data.
                return stream({}, string.rep('B',288))
            end
            error('Unexpected guest file: '..path)
        end,
    }
    local mock_lfs = {
        dir=function(path)
            assert(path == '/etc/keys')
            local done = false
            return function() if not done then done=true; return 'apps.pub' end end
        end,
        attributes=function(path, attribute)
            if path == '/etc/keys/apps.pub' then return {mode='file'} end
            if path == '/fs/usb0/swdlInstall.iso' then
                assert(attribute == 'mode')
                return options.pair and 'file' or nil
            end
            if path == '/fs/etfs/ALLOW_DOWNGRADES' then return nil end
            error('Unexpected guest attributes: '..path)
        end,
    }
    local mock_onoff = {}
    for _, name in ipairs({'setDisplaySetting', 'resetUpdateInProgress',
                           'setUpdateMode', 'setConvertMode'}) do
        mock_onoff[name] = function(value)
            assert(value == nil or value == false)
        end
    end
    local modules = {string=string, lfs=mock_lfs, service=mock_service,
        onoff=mock_onoff, mcd={notify=function(rule, fn) callbacks[rule]=fn end}}
    local loader_env = base()
    loader_env.io, loader_env.os = mock_io, mock_os
    loader_env.require = function(name) return assert(modules[name], name) end
    loader_env.module = function(name)
        assert(name == 'loader'); setfenv(2, loader_env)
    end
    loader_env.loadfile = function(path)
        assert(path == '/fs/swdl/etc/manifest.lua')
        trace.manifests = trace.manifests + 1
        event('manifest:'..(options.pair and 'installer' or 'updater'))
        return setfenv(assert(loadstring(sources[options.pair and 2 or 1])), {})
    end
    run(sources[3], loader_env)
    modules.loader = loader_env
    local env = base()
    env.io, env.os, env.require = mock_io, mock_os, loader_env.require
    run(sources[4], env)
    if options.app then
        -- A direct table input isolates this dispatch branch. It is not an ISO.
        loader_env.isoDir, loader_env.usbDir = '/fs/swdl', '/fs/usb0'
        env.processManifest({version='6.17.0WL', external={start_script=app_script}},
                            '/fs/usb0/swdlInstall.iso')
    else
        assert(callbacks.SWDL)('/fs/usb0')
    end
    assert(methods)
    trace.status = methods.getStatus().state
    return trace
end
local function case(name, options, check)
    local trace = bounded(function() return resident(options) end)
    check(trace)
    trace.name = name
    results[#results+1] = trace
end
case('stock_pair_full_verifier_failure', {pair=true, full_status=256}, function(t)
    assert(t.fast_checks == 2 and t.full_checks == 1 and t.manifests == 1)
    assert(t.external_calls == 1 and t.sam_checks == 0)
    assert(t.external_script == '/fs/swdl/'..nav_script)
end)
case('updater_only_full_verifier_failure', {full_status=256}, function(t)
    assert(t.fast_checks == 1 and t.full_checks == 1 and t.manifests == 1)
    assert(t.external_calls == 0 and t.status == 'updateMediaAvailable')
end)
for gate = 1, 2 do
    case('fast_signature_'..gate..'_rejected', {pair=true, fail_fast=gate}, function(t)
        assert(t.fast_checks == gate and t.full_checks == 0)
        assert(t.mounts == 0 and t.manifests == 0 and t.external_calls == 0)
        assert(t.error == 'Software Update : Authentication failed')
    end)
end
case('mount_failure', {pair=true, mount_fail=true}, function(t)
    assert(t.mounts == 1 and t.manifests == 0 and t.external_calls == 0)
    assert(t.error == 'Software Update : Mount iso failed')
end)
case('app_signature_rejected', {app=true}, function(t)
    assert(t.sam_checks == 1 and t.external_calls == 0)
    assert(t.error == 'Software Update : Authentication failed')
end)
case('app_signature_success_unequal_mock_hashes', {app=true, sam_ok=true}, function(t)
    assert(t.sam_checks == 1 and t.external_calls == 1)
    assert(t.external_script == '/fs/swdl/'..app_script)
end)

local auth_results = {}
local function auth(name, lines, close_status, expected_exit)
    local env, exit_marker, code, commands = base(), {}, nil, 0
    local modules = {
        service={register=function() return 'mock-service' end, emit=function() end},
        mcd={notify=function() end}, onoff={}, dumper={dumpTable=function() end},
        lfs={attributes=function(path)
            if path == '/fs/usb0/swdlInstall.iso' then return 'file' end
            if path == '/fs/usb0' then return 'directory' end
            error('Unexpected auth path: '..path)
        end},
    }
    env.arg = {'/fs/usb0/swdlInstall.iso', '/fs/usb0'}
    env.require = function(module) return assert(modules[module], module) end
    env.os = {exit=function(value) code=value; error(exit_marker) end}
    env.io = {popen=function(cmd, mode)
        assert(cmd == 'verifyISO sha256 /fs/usb0/swdlInstall.iso' and mode == 'r')
        commands = commands + 1
        return stream(lines, nil, close_status)
    end}
    bounded(function()
        local ok, err = pcall(function() run(sources[5], env) end)
        assert(not ok and err == exit_marker, tostring(err))
    end)
    assert(commands == 1 and code == expected_exit)
    auth_results[#auth_results+1] = {name=name, exit_code=code,
        verifier_stdout=lines, mocked_close_status=close_status}
end
auth('explicit_success', {'50', 'ISO Verified OK.'}, 0, 0)
auth('explicit_error', {'ERROR: signature verification failed'}, 256, 6)
auth('missing_success_marker', {'50', '100'}, 0, 6)
auth('empty_output', {}, 256, 6)
auth('success_marker_nonzero_close', {'ISO Verified OK.'}, 256, 0)

local function json(value, array)
    if type(value) == 'string' then
        return '"'..value:gsub('[%z\1-\31\\"]', function(c)
            return string.format('\\u%04x', string.byte(c))
        end)..'"'
    end
    if type(value) == 'number' or type(value) == 'boolean' then return tostring(value) end
    assert(type(value) == 'table')
    local out = {}
    if #value > 0 or array then
        for _, v in ipairs(value) do out[#out+1] = json(v) end
        return '['..table.concat(out, ',')..']'
    end
    local keys = {}
    for k in pairs(value) do keys[#keys+1] = k end
    table.sort(keys)
    for _, k in ipairs(keys) do
        out[#out+1] = json(k)..':'..json(value[k], k == 'verifier_stdout')
    end
    return '{'..table.concat(out, ',')..'}'
end
print(json({manifest=install, resident_cases=results, authentication_cases=auth_results,
    passed_cases=#results+#auth_results+1}))
