-- Execute only the pinned plaintext loader inside mocked QNX services.
-- Every guest filesystem operation and shell command is intercepted.
local loader_path, marker_path = assert(arg[1]), assert(arg[2])
local f = assert(io.open(marker_path, 'rb'))
local marker = f:read('*all')
f:close()
local source = assert(loadfile(loader_path))
local registration, received, verify_called, manifest_called
local fast_ok = true
local events = {}
local function record(value) events[#events+1] = value end
local function stream(lines)
    return { lines=function()
        local i = 0
        return function() i=i+1; return lines[i] end
    end, close=function() end }
end
local mock_os = {
    execute=function(cmd)
        if cmd:find('/usr/bin/verifyISO',1,true) then
            verify_called = true
            record('full_verifier_returned_failure')
            return 256
        end
        if cmd:find('inject ',1,true)==1 or cmd:find('isodigest ',1,true)==1 or cmd:find('rm -f /tmp/',1,true)==1 then return 0 end
        error('Unexpected mocked command: '..cmd)
    end,
    mount=function() record('mount_requested'); return true end,
    umount=function() record('unmount_requested'); return true end,
}
local mock_io = {
    popen=function(cmd)
        assert(cmd:find('openssl dgst -sha256 -verify ',1,true)==1)
        -- Cryptographic results are independently checked by the Python driver.
        record(fast_ok and 'fast_signature_accepted' or 'fast_signature_rejected')
        return stream({fast_ok and 'Verified OK' or 'Verification failure'})
    end
}
local mock_lfs = {
    dir=function()
        local used = false
        return function() if not used then used=true; return 'apps.pub' end end
    end,
    attributes=function(path,attribute)
        if path=='/etc/keys/apps.pub' then return {mode='file'} end
        if path=='/fs/usb0/swdlInstall.iso' then return nil end
        error('Unexpected mocked path: '..path)
    end
}
local modules = {string=string,lfs=mock_lfs,service={},
    mcd={notify=function(name,fn) assert(name=='SWDL'); registration=fn end}}
local env = {io=mock_io,os=mock_os,string=string,
    assert=assert,ipairs=ipairs,pairs=pairs,pcall=pcall,type=type,
    print=function() end,require=function(name) return assert(modules[name],name) end,
    loadfile=function(path)
        assert(path=='/fs/swdl/etc/manifest.lua')
        manifest_called=true
        record('manifest_load_requested')
        return setfenv(assert(loadstring(marker,'local-research-marker')), {})
    end}
env.module=function(name) assert(name=='loader'); setfenv(2,env) end
setfenv(source,env)()
env.notifyOnInsert(function(manifest) received=manifest; record('callback_reached') end)
registration('/fs/usb0')
assert(verify_called and manifest_called)
assert(received and received.research_probe=='GT86_LOCAL_ONLY')
print('PASS: existing resident loader reached the harmless manifest after full verifier failure')
print(table.concat(events,' -> '))
-- Negative control: the first signature gate must actually prevent loading.
fast_ok=false; verify_called=false; manifest_called=false; received=nil
registration('/fs/usb0')
assert(not verify_called and not manifest_called and received==nil)
print('PASS: first signature failure prevented manifest loading')
