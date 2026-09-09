/* SPDX-License-Identifier: GPL-3.0-only
 * Actual Windows I/O, only newly created private test paths and PUBLIC keys.
 * Exact owned files are removed on success; no recursive deletion/real records.
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#include <winioctl.h>
#include <filesystem>
#include "pair_store_file.h"
#include "pair_setup_channel.h"
#include "projection_control.h"
#include "pair_test_support.h"
// Report the original assertion before unwinding: this Windows Clang runtime
// can otherwise mask an assertion with a C++ exception alignment diagnostic.
#undef CHECK
#define CHECK(x) do { if(!(x)) { std::cerr<<#x<<" line "<<__LINE__<<" Windows="<<GetLastError()<<'\n';std::abort(); } } while(0)
namespace fs=std::filesystem;
template<class T> static auto object_bytes(const T& value) { std::array<uint8_t,sizeof(T)> out{};std::memcpy(out.data(),&value,sizeof(T));return out; }
struct Temporary {
    std::string directory;std::vector<std::string> files,dirs;
    explicit Temporary(const char* root) {
        directory=(fs::canonical(root)/("pair-store-test-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(GetTickCount64()))).string();
        uint32_t error=0;CHECK(pair_store_directory_create(directory.c_str(),&error)==IAP2_OK&&error==0);
    }
    std::string path(const std::string& name) { CHECK(!name.empty()&&name.find_first_of("/\\:")==std::string::npos);auto p=(fs::path(directory)/name).string();files.push_back(p);return p; }
    std::string subdir(const std::string& name,bool private_dir=true) { auto p=(fs::path(directory)/name).string();
        if(private_dir) CHECK(pair_store_directory_create(p.c_str(),nullptr)==IAP2_OK);else CHECK(CreateDirectoryA(p.c_str(),nullptr));dirs.push_back(p);return p; }
    void cleanup() {
        for(auto i=files.rbegin();i!=files.rend();++i) if(!DeleteFileA(i->c_str())) CHECK(GetLastError()==ERROR_FILE_NOT_FOUND);
        for(auto i=dirs.rbegin();i!=dirs.rend();++i) CHECK(RemoveDirectoryA(i->c_str()));CHECK(RemoveDirectoryA(directory.c_str()));
    }
};
struct Store {
    pair_store_file s{};pair_store_file_view view{};
    ~Store() { if(s.state==PAIR_STORE_FILE_ACTIVE||s.state==PAIR_STORE_FILE_POISONED) (void)pair_store_file_close(view); }
    // Explicitly initialize padding too: byte-transactionality checks cannot use
    // unspecified C++ aggregate padding as their expected object representation.
    Store() { pair_crypto_wipe(&s,sizeof(s)); }Store(const Store&)=delete;Store& operator=(const Store&)=delete;
    void create(const std::string& p,const pair_store_data& initial,uint64_t gen=1) { uint32_t e=0;int r=pair_store_file_create(&s,p.c_str(),&initial,gen,&e);
        if(r!=IAP2_OK) throw std::runtime_error("create result="+std::to_string(r)+" Windows="+std::to_string(e));
        CHECK(pair_store_file_view_init(&view,&s,gen)==IAP2_OK); }
    void open(const std::string& p,uint64_t gen) { uint32_t e=0;int r=pair_store_file_open(&s,p.c_str(),gen,&e);
        if(r!=IAP2_OK) throw std::runtime_error("open result="+std::to_string(r)+" Windows="+std::to_string(e));
        CHECK(pair_store_file_view_init(&view,&s,gen)==IAP2_OK); }
    void close() { CHECK(pair_store_file_close(view)==IAP2_OK&&zeroed(&s.data,sizeof(s.data))&&s.handle==0&&s.ancestor_count==0); }
    int commit(const Bytes& id,const Bytes& pk) { CHECK(pk.size()==32);pair_store_file_binding binding{};
        CHECK(pair_store_file_bind(&binding,view,91,77)==IAP2_OK);return pair_store_file_commit(&binding,91,77,id.data(),id.size(),pk.data()); }
};
static pair_store_data initial(const Vectors& v) { pair_store_data s{};const auto& id=v.at("pv_own_identifier");
    CHECK(pair_store_init(&s,v.at("pv_own_seed").data(),v.at("pv_own_public").data(),id.data(),id.size())==IAP2_OK);return s; }
static Bytes read_file(const std::string& p) { std::ifstream f(p,std::ios::binary);CHECK(f.good());return {std::istreambuf_iterator<char>(f),{}}; }
// Deliberate fault/corruption of known NEW synthetic test files, never user data.
static void replace_test_file(const std::string& p,const Bytes& b) { std::ofstream f(p,std::ios::binary|std::ios::trunc);CHECK(f.good());f.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size()));f.close();CHECK(f.good()); }
static void second_process(const std::string& path,bool locked) {
    char exe[PAIR_STORE_PATH_MAX]{};CHECK(GetModuleFileNameA(nullptr,exe,sizeof(exe))<sizeof(exe));
    auto command=std::string("\"")+exe+"\" "+(locked?"--locked":"--reopen")+" \""+path+"\"";
    STARTUPINFOA startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
    CHECK(CreateProcessA(exe,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process));
    auto wait=WaitForSingleObject(process.hProcess,30000);DWORD status=999;
    if(wait!=WAIT_OBJECT_0) { TerminateProcess(process.hProcess,2);WaitForSingleObject(process.hProcess,5000); }
    CHECK(GetExitCodeProcess(process.hProcess,&status));CloseHandle(process.hThread);CloseHandle(process.hProcess);CHECK(wait==WAIT_OBJECT_0&&status==0);
}
static void junction(const std::string& fresh_directory,const std::string& owned_target) {
    // Mount-point reparse format from Microsoft's REPARSE_DATA_BUFFER. Both
    // paths were explicitly created by this test; no shell, privilege changes
    // or links to user data. RemoveDirectory removes only this junction later.
    std::wstring target=L"\\??\\"+fs::path(owned_target).wstring();auto label=fs::path(owned_target).wstring();
    struct MountPoint { DWORD tag;WORD length,reserved,sub_offset,sub_length,print_offset,print_length;WCHAR paths[1024]; } data{};
    static_assert(offsetof(MountPoint,paths)==16);CHECK(target.size()+label.size()+2<1024);
    data.tag=IO_REPARSE_TAG_MOUNT_POINT;data.sub_length=static_cast<WORD>(target.size()*2);data.print_offset=data.sub_length+2;data.print_length=static_cast<WORD>(label.size()*2);
    data.length=static_cast<WORD>(8+data.sub_length+2+data.print_length+2);
    std::copy(target.begin(),target.end(),data.paths);std::copy(label.begin(),label.end(),data.paths+target.size()+1);
    HANDLE h=CreateFileA(fresh_directory.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);CHECK(h!=INVALID_HANDLE_VALUE);
    DWORD returned=0;BOOL result=DeviceIoControl(h,FSCTL_SET_REPARSE_POINT,&data,8u+data.length,nullptr,0,&returned,nullptr);auto error=GetLastError();CloseHandle(h);
    if(!result) std::cerr<<"junction error="<<error<<'\n';CHECK(result);
}
static void persistence(Temporary& tmp,const Vectors& v) {
    auto p=tmp.path("persist.bin");auto seed=initial(v);Store s;s.create(p,seed);auto identity=pair_store_file_identity(&s.view);CHECK(identity&&s.s.data.count==0);
    uint8_t signature[64]{};const auto message=bytes("stable across reopen");CHECK(pair_identity_sign(identity,message.data(),message.size(),signature)==IAP2_OK);
    Store other;uint32_t error=0;auto old=object_bytes(other.s);
    CHECK(pair_store_file_open(&other.s,p.c_str(),1,&error)==IAP2_PROVIDER_FAILED&&error==ERROR_SHARING_VIOLATION&&object_bytes(other.s)==old);
    second_process(p,true);
    auto renamed=p+".moved";BOOL moved=MoveFileA(p.c_str(),renamed.c_str());if(moved) CHECK(MoveFileA(renamed.c_str(),p.c_str()));CHECK(!moved);
    renamed=tmp.directory+"-moved";moved=MoveFileA(tmp.directory.c_str(),renamed.c_str());if(moved) CHECK(MoveFileA(renamed.c_str(),tmp.directory.c_str()));CHECK(!moved);
    pair_store_file_binding binding{};CHECK(pair_store_file_bind(&binding,s.view,91,77)==IAP2_OK);auto before=object_bytes(binding);
    const auto& id=v.at("pv_ctrl_identifier");const auto& key=v.at("pv_ctrl_public");
    CHECK(pair_store_file_commit(&binding,92,77,id.data(),id.size(),key.data())==IAP2_INVALID&&object_bytes(binding)==before);
    CHECK(pair_store_file_commit(&binding,91,78,id.data(),id.size(),key.data())==IAP2_INVALID&&!binding.used);
    uint8_t bad=0;CHECK(pair_store_file_commit(&binding,91,77,&bad,1,key.data())==IAP2_ARGUMENT&&!binding.used);
    CHECK(pair_store_file_commit(&binding,91,77,id.data(),id.size(),key.data())==IAP2_OK&&binding.used&&s.s.data.count==1);
    CHECK(pair_store_file_identity(&s.view)==identity);uint8_t after[64]{};CHECK(pair_identity_sign(identity,message.data(),message.size(),after)==IAP2_OK&&std::memcmp(signature,after,64)==0);
    CHECK(pair_store_file_commit(&binding,91,77,id.data(),id.size(),key.data())==IAP2_INVALID);
    CHECK(s.commit(id,key)==IAP2_OK&&s.s.data.revision==2&&s.commit(id,v.at("pv_own_public"))==PAIR_STORE_CONFLICT&&s.s.data.revision==2);
    auto stale=s.view;pair_store_file_binding stale_binding{};CHECK(pair_store_file_bind(&stale_binding,s.view,93,79)==IAP2_OK);
    s.close();auto saved=read_file(p);CHECK(saved.size()==PAIR_STORE_IMAGE_SIZE*2);second_process(p,false);
    s.open(p,2);uint8_t found[32]{};CHECK(pair_store_file_lookup(&s.view,id.data(),id.size(),found)==IAP2_OK&&equal(found,key));
    identity=pair_store_file_identity(&s.view);CHECK(pair_identity_sign(identity,message.data(),message.size(),after)==IAP2_OK&&std::memcmp(signature,after,64)==0);
    auto state=object_bytes(s.s);CHECK(pair_store_file_close(stale)==IAP2_INVALID&&object_bytes(s.s)==state);
    CHECK(pair_store_file_lookup(&stale,id.data(),id.size(),found)==IAP2_INVALID&&zeroed(found,32)&&!pair_store_file_identity(&stale));
    CHECK(pair_store_file_commit(&stale_binding,93,79,id.data(),id.size(),key.data())==IAP2_INVALID&&!stale_binding.used);
    CHECK(pair_store_file_create(&other.s,p.c_str(),&seed,1,&error)==IAP2_PROVIDER_FAILED);s.close();
    CHECK(pair_store_file_create(&other.s,p.c_str(),&seed,1,&error)==IAP2_PROVIDER_FAILED&&error==ERROR_FILE_EXISTS&&read_file(p)==saved);
    CHECK(pair_store_file_open(&s.s,p.c_str(),2,&error)==IAP2_ARGUMENT);pair_store_clear(&seed);pair_crypto_wipe(&state,sizeof(state));
}
static void policy(Temporary& tmp,const Vectors& v) {
    auto seed=initial(v);Store s;uint32_t error=0;auto p=tmp.path("missing.bin");auto before=object_bytes(s.s);
    CHECK(pair_store_file_open(&s.s,p.c_str(),1,&error)==IAP2_PROVIDER_FAILED&&error==ERROR_FILE_NOT_FOUND&&!fs::exists(p));
    const std::vector<std::string> invalid={"relative.bin","C:relative.bin","\\\\server\\share\\x","\\\\?\\C:\\x","C:\\NUL","C:\\CON.txt","C:\\com1.log","C:\\LPT9","C:\\CON .txt","C:\\CONIN$","C:\\CONOUT$",p+":stream",tmp.directory+"\\..\\escape",tmp.directory+"\\.\\x",tmp.directory+"\\x.",tmp.directory+"\\x ",tmp.directory+"\\\\x",tmp.directory+"\\x?",std::string("C:\\")+char(0x80)+"x",std::string(260,'a')};
    for(const auto& path:invalid) CHECK(pair_store_file_create(&s.s,path.c_str(),&seed,1,&error)==IAP2_ARGUMENT&&object_bytes(s.s)==before);
    auto dirty=seed;dirty.seed[0]^=1;CHECK(pair_store_file_create(&s.s,p.c_str(),&dirty,1,&error)==IAP2_AUTH_FAILED&&!fs::exists(p));
    dirty=seed;CHECK(pair_store_add(&dirty,v.at("pv_ctrl_identifier").data(),v.at("pv_ctrl_identifier").size(),v.at("pv_ctrl_public").data())==IAP2_OK);
    CHECK(pair_store_file_create(&s.s,p.c_str(),&dirty,1,&error)==IAP2_ARGUMENT&&!fs::exists(p));
    CHECK(pair_store_directory_create(tmp.directory.c_str(),&error)==IAP2_PROVIDER_FAILED&&error==ERROR_ALREADY_EXISTS);
    auto ordinary=tmp.subdir("inherited",false);auto denied=(fs::path(ordinary)/"denied.bin").string();
    CHECK(pair_store_file_create(&s.s,denied.c_str(),&seed,1,&error)==IAP2_AUTH_FAILED&&error==ERROR_ACCESS_DENIED&&!fs::exists(denied));
    auto permissive=tmp.path("permissive.bin");s.create(permissive,seed);s.close();auto saved=read_file(permissive);
    CHECK(SetNamedSecurityInfoA(permissive.data(),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS);
    CHECK(pair_store_file_open(&s.s,permissive.c_str(),2,&error)==IAP2_AUTH_FAILED&&read_file(permissive)==saved);
    auto source=tmp.path("hardlink-source.bin"),link=tmp.path("hardlink.bin");Store hard;hard.create(source,seed);hard.close();CHECK(CreateHardLinkA(link.c_str(),source.c_str(),nullptr));
    CHECK(pair_store_file_open(&hard.s,source.c_str(),2,&error)==IAP2_AUTH_FAILED&&pair_store_file_open(&hard.s,link.c_str(),2,&error)==IAP2_AUTH_FAILED);
    auto mount=tmp.subdir("junction");junction(mount,ordinary);auto through_mount=(fs::path(mount)/"never.bin").string();
    CHECK(pair_store_file_create(&s.s,through_mount.c_str(),&seed,2,&error)==IAP2_AUTH_FAILED&&!fs::exists(through_mount));
    CHECK(pair_store_file_open(&s.s,mount.c_str(),2,&error)!=IAP2_OK);
    std::cout<<"PASS: actual directory junction/reparse traversal refused\n";
    // Symlinks need Developer Mode or privilege on Windows; explicitly report a
    // skipped check instead of claiming reparse execution when unavailable.
    auto sym=(fs::path(tmp.directory)/"reparse").string();
    if(CreateSymbolicLinkA(sym.c_str(),ordinary.c_str(),SYMBOLIC_LINK_FLAG_DIRECTORY|2u)) {
        tmp.dirs.push_back(sym);auto through=(fs::path(sym)/"never.bin").string();
        CHECK(pair_store_file_create(&s.s,through.c_str(),&seed,2,&error)==IAP2_AUTH_FAILED&&!fs::exists(through));
        std::cout<<"PASS: directory reparse point refused\n";
    } else { CHECK(GetLastError()==ERROR_PRIVILEGE_NOT_HELD);std::cout<<"SKIP: symlink creation lacks Windows privilege; reparse path check not exercised\n"; }
    pair_store_clear(&seed);pair_store_clear(&dirty);
}
static void journal_corruption(Temporary& tmp,const Vectors& v) {
    auto seed=initial(v);auto p=tmp.path("corruption.bin");Store s;s.create(p,seed);
    CHECK(s.commit(v.at("pv_ctrl_identifier"),v.at("pv_ctrl_public"))==IAP2_OK);CHECK(s.commit(bytes("second"),v.at("pv_own_public"))==IAP2_OK);s.close();
    auto valid=read_file(p);CHECK(valid.size()==3*PAIR_STORE_IMAGE_SIZE);
    std::vector<Bytes> bads={Bytes{},Bytes(valid.begin(),valid.begin()+23),Bytes(valid.begin(),valid.end()-1),Bytes(valid.begin(),valid.begin()+PAIR_STORE_IMAGE_SIZE+23),Bytes(PAIR_STORE_MAX_FILE_SIZE+1),Bytes(valid.begin()+PAIR_STORE_IMAGE_SIZE,valid.end())};
    auto mutated=valid;mutated[24]^=1;bads.push_back(mutated);mutated=valid;mutated[PAIR_STORE_IMAGE_SIZE+100]^=1;bads.push_back(mutated);
    // Individually valid but reordered/non-prefix histories, not just bad hashes.
    mutated=valid;std::swap_ranges(mutated.begin()+PAIR_STORE_IMAGE_SIZE,mutated.begin()+2*PAIR_STORE_IMAGE_SIZE,mutated.begin()+2*PAIR_STORE_IMAGE_SIZE);bads.push_back(mutated);
    auto alternative=seed;CHECK(pair_store_add(&alternative,v.at("pv_ctrl_identifier").data(),v.at("pv_ctrl_identifier").size(),v.at("pv_own_public").data())==IAP2_OK);
    mutated=valid;CHECK(pair_store_encode(&alternative,mutated.data()+PAIR_STORE_IMAGE_SIZE,PAIR_STORE_IMAGE_SIZE)==IAP2_OK);bads.push_back(mutated);
    for(const auto& bad:bads) { replace_test_file(p,bad);Store fresh;auto before=object_bytes(fresh.s);uint32_t error=0;
        auto result=pair_store_file_open(&fresh.s,p.c_str(),1,&error);
        if(result!=PAIR_STORE_CORRUPT) std::cerr<<"corrupt length="<<bad.size()<<" result="<<result<<" error="<<error<<'\n';
        CHECK(result==PAIR_STORE_CORRUPT&&object_bytes(fresh.s)==before&&read_file(p)==bad); }
    // Exact-boundary rollback cannot be detected without an external counter.
    replace_test_file(p,Bytes(valid.begin(),valid.begin()+PAIR_STORE_IMAGE_SIZE));s.open(p,2);CHECK(s.s.data.count==0);s.close();
    replace_test_file(p,valid);s.open(p,3);CHECK(s.s.data.count==2);s.close();pair_store_clear(&seed);pair_store_clear(&alternative);
}
static void capacity(Temporary& tmp,const Vectors& v) {
    auto seed=initial(v);auto p=tmp.path("capacity.bin");Store s;s.create(p,seed);
    for(unsigned i=0;i<PAIR_STORE_MAX_CONTROLLERS;++i) CHECK(s.commit(bytes("phone-"+std::to_string(i)),v.at("pv_ctrl_public"))==IAP2_OK);
    CHECK(s.commit(bytes("excess"),v.at("pv_ctrl_public"))==IAP2_NO_SPACE&&s.s.data.count==16);
    CHECK(s.commit(bytes("phone-0"),v.at("pv_ctrl_public"))==IAP2_OK&&s.s.data.revision==17);s.close();
    auto saved=read_file(p);CHECK(saved.size()==PAIR_STORE_MAX_FILE_SIZE);s.open(p,2);CHECK(s.s.data.count==16);s.close();CHECK(read_file(p)==saved);pair_store_clear(&seed);
}
#ifdef PAIR_STORE_TESTING
static void creation_interruptions(Temporary& tmp,const Vectors& v) {
    for(unsigned point=1;point<=4;++point) {
        auto seed=initial(v);auto p=tmp.path("initial-"+std::to_string(point)+".bin");Store s;uint32_t error=0;
        CHECK(pair_store_file_test_initial_fault(&s.s,point)==IAP2_OK);auto saved=object_bytes(s.s);
        CHECK(pair_store_file_create(&s.s,p.c_str(),&seed,1,&error)==PAIR_STORE_UNCERTAIN&&error==ERROR_WRITE_FAULT&&object_bytes(s.s)==saved);
        auto b=read_file(p);CHECK(b.size()==(point==1?0u:(point==2?23u:PAIR_STORE_IMAGE_SIZE)));
        CHECK(pair_store_file_create(&s.s,p.c_str(),&seed,1,&error)==IAP2_PROVIDER_FAILED&&error==ERROR_FILE_EXISTS&&read_file(p)==b);
        if(point<=2) CHECK(pair_store_file_open(&s.s,p.c_str(),1,&error)==PAIR_STORE_CORRUPT&&read_file(p)==b);
        else { s.open(p,1);CHECK(s.s.data.count==0&&equal(s.s.data.identity.public_key,v.at("pv_own_public")));s.close(); }
        pair_store_clear(&seed);
    }
}
#endif
struct Random { const Vectors& v;bool verify=false;int calls=0;static int read(void* p,uint8_t* out,size_t n) { auto& r=*static_cast<Random*>(p);++r.calls;
    const auto& b=r.v.at(r.verify?"pv_own_ephemeral_secret":(n==16?"salt":"b"));CHECK(b.size()==n);std::copy(b.begin(),b.end(),out);return 0; } };
static Bytes outer(const Bytes& body,unsigned step,const char* route) {
    auto b=bytes(std::string("POST ")+route+" RTSP/1.0\r\nCSeq: "+std::to_string(step)+"\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n");b.insert(b.end(),body.begin(),body.end());return b;
}
static void verify_reopened(Store& store,const Vectors& v) {
    projection_control c{};projection_control_config cfg{};projection_control_default_config(&cfg);cfg.cipher.payload_limit=256;
    Bytes rx(2048),tx(2048),crx(274),plain(256),ctx(274);projection_control_storage storage={rx.data(),tx.data(),crx.data(),plain.data(),ctx.data(),rx.size(),tx.size(),crx.size(),plain.size(),ctx.size()};
    Random rng{v,true};CHECK(projection_control_init(&c,pair_store_file_identity(&store.view),Random::read,&rng,pair_store_file_lookup,&store.view,&cfg,&storage,92,0)==IAP2_OK);
    for(unsigned step:{1u,3u}) {
        auto body=outer(v.at("pv_m"+std::to_string(step)),step,"/pair-verify");size_t used=0;
        CHECK(projection_control_feed(&c,92,body.data(),body.size(),&used,1)==RTSP_CHANNEL_OUTPUT&&used==body.size());
        rtsp_slice out{};rtsp_channel_key key{};CHECK(projection_control_output(&c,92,&out,&key,1)==RTSP_CHANNEL_OUTPUT);rtsp_message reply{};
        CHECK(rtsp_message_decode(out.data,out.size,&reply,&used)==IAP2_OK&&Bytes(reply.body.data,reply.body.data+reply.body.size)==v.at("pv_m"+std::to_string(step+1)));
        CHECK(projection_control_consume(&c,key,out.size,1)==RTSP_CHANNEL_OUTPUT_DONE);
        CHECK(projection_control_release(&c,key,1)==(step==1?IAP2_OK:PROJECTION_CONTROL_SECURE));
    }
    auto request=bytes("GET /info RTSP/1.0\r\nCSeq: 9\r\n\r\n");Bytes frame(request.size()+18);frame[0]=static_cast<uint8_t>(request.size());uint8_t nonce[12]{};size_t n=0;
    CHECK(pair_aead_seal(v.at("pv_accessory_read_key").data(),nonce,frame.data(),2,request.data(),request.size(),frame.data()+2,frame.size()-2,&n)==IAP2_OK);
    CHECK(projection_control_feed(&c,92,frame.data(),frame.size(),&n,1)==RTSP_CHANNEL_REQUEST&&n==frame.size());
    rtsp_message req{};rtsp_channel_key key{};CHECK(projection_control_request(&c,&req,&key)==RTSP_CHANNEL_REQUEST&&req.cseq==9);
    rtsp_response response={501,{},nullptr,0,{}};CHECK(projection_control_respond(&c,key,&response,1)==RTSP_CHANNEL_OUTPUT);rtsp_slice out{};
    CHECK(projection_control_output(&c,92,&out,&key,1)==RTSP_CHANNEL_OUTPUT);Bytes decoded(256);
    CHECK(pair_aead_open(v.at("pv_accessory_write_key").data(),nonce,out.data,2,out.data+2,out.size-2,decoded.data(),decoded.size(),&n)==IAP2_OK);size_t used=0;
    CHECK(rtsp_message_decode(decoded.data(),n,&req,&used)==IAP2_OK&&req.status==501&&req.cseq==9);
    CHECK(projection_control_consume(&c,key,out.size,1)==RTSP_CHANNEL_OUTPUT_DONE&&projection_control_release(&c,key,1)==IAP2_OK);projection_control_close(&c);
}
static void enrollment_and_interruptions(Temporary& tmp,const Vectors& v) {
    // 0 success, 1 prewrite, 2 actual prefix only, 3 full unflushed, 4 flushed but
    // unacknowledged, 5 denied, 6 approved commit with deliberately lost M6.
    for(unsigned mode=0;mode<=6;++mode) {
#ifndef PAIR_STORE_TESTING
        if(mode>=1&&mode<=4) continue;
#endif
        auto seed=initial(v);auto p=tmp.path("enroll-"+std::to_string(mode)+".bin");Store s;s.create(p,seed);
        pair_store_file_binding binding{};CHECK(pair_store_file_bind(&binding,s.view,91,77)==IAP2_OK);
        Random rng{v};pair_setup_channel channel{};pair_setup_channel_config cfg{};pair_setup_channel_default_config(&cfg);Bytes rx(2048),tx(2048);
        CHECK(pair_setup_channel_init(&channel,pair_store_file_identity(&s.view),Random::read,&rng,pair_store_file_commit,&binding,
            pair_store_file_lookup,&s.view,&cfg,rx.data(),rx.size(),tx.data(),tx.size(),91,0)==IAP2_OK);
        CHECK(pair_setup_channel_authorize(&channel,91,77,1)==IAP2_OK);
        for(unsigned step:{1u,3u,5u}) {
            auto wire=outer(v.at("setup_"+std::to_string(step)),step,"/pair-setup");size_t offset=0;int r=IAP2_MORE;
            while(r==IAP2_MORE) { size_t n=0;r=pair_setup_channel_feed(&channel,91,wire.data()+offset,std::min(size_t(7),wire.size()-offset),&n,1);offset+=n; }
            CHECK(offset==wire.size()&&r==(step==5?PAIR_SETUP_APPROVAL:RTSP_CHANNEL_OUTPUT));rtsp_channel_key key{};rtsp_slice out{};
            if(step==5) {
                pair_setup_candidate candidate{};CHECK(pair_setup_channel_pending(&channel,&candidate,&key)==PAIR_SETUP_APPROVAL);
                CHECK(s.s.data.count==0&&!binding.used&&equal(candidate.public_key,v.at("pv_ctrl_public")));
#ifdef PAIR_STORE_TESTING
                if(mode>=1&&mode<=4) CHECK(pair_store_file_test_fault(s.view,mode)==IAP2_OK);
#endif
                r=pair_setup_channel_decide(&channel,key,mode!=5,1);
                if(mode>=1&&mode<=5) {
                    CHECK(r==PAIR_SETUP_CLOSED&&!channel.setup.committed&&zeroed(channel.setup.output,sizeof(channel.setup.output)));
                    if(mode<=4) { CHECK(channel.setup.last_error==PAIR_STORE_UNCERTAIN&&binding.used&&s.s.state==PAIR_STORE_FILE_POISONED&&s.s.data.count==0);
                        CHECK(!pair_store_file_identity(&s.view));uint8_t pk[32]{};
                        CHECK(pair_store_file_lookup(&s.view,v.at("pv_ctrl_identifier").data(),v.at("pv_ctrl_identifier").size(),pk)==PAIR_STORE_CLOSED&&zeroed(pk,32));
                        pair_store_file_binding retry{};CHECK(pair_store_file_bind(&retry,s.view,93,79)==PAIR_STORE_CLOSED&&zeroed(&retry,sizeof(retry)));
                    } else CHECK(!binding.used&&s.s.state==PAIR_STORE_FILE_ACTIVE);
                    break;
                }
                CHECK(r==RTSP_CHANNEL_OUTPUT&&channel.setup.committed&&binding.used&&s.s.data.count==1);
                if(mode==6) break;
            }
            Bytes sent;int r2;
            while((r2=pair_setup_channel_output(&channel,91,&out,&key,1))==RTSP_CHANNEL_OUTPUT) {
                size_t n=std::min(size_t(3),out.size);sent.insert(sent.end(),out.data,out.data+n);auto retired=pair_setup_channel_consume(&channel,key,n,1);
                CHECK(retired==RTSP_CHANNEL_OUTPUT||retired==RTSP_CHANNEL_OUTPUT_DONE);
            }
            CHECK(r2==RTSP_CHANNEL_OUTPUT_DONE);rtsp_message reply{};size_t n=0;
            CHECK(rtsp_message_decode(sent.data(),sent.size(),&reply,&n)==IAP2_OK&&Bytes(reply.body.data,reply.body.data+reply.body.size)==v.at("setup_"+std::to_string(step+1)));
            CHECK(pair_setup_channel_release(&channel,key,1)==(step==5?PAIR_SETUP_COMPLETE:IAP2_OK));
        }
        pair_setup_channel_close(&channel);s.close();auto saved=read_file(p);uint32_t error=0;
        if(mode==2) { CHECK(saved.size()==PAIR_STORE_IMAGE_SIZE+23);CHECK(pair_store_file_open(&s.s,p.c_str(),2,&error)==PAIR_STORE_CORRUPT&&read_file(p)==saved); }
        else { s.open(p,2);unsigned expected=(mode==1||mode==5)?0u:1u;CHECK(s.s.data.count==expected);
            if(expected) verify_reopened(s,v);s.close();CHECK(read_file(p)==saved); }
        pair_store_clear(&seed);
    }
}
int main(int argc,char** argv) { try {
    if(argc==3&&(std::string(argv[1])=="--locked"||std::string(argv[1])=="--reopen")) {
        Store s;uint32_t error=0;int r=pair_store_file_open(&s.s,argv[2],1,&error);
        if(std::string(argv[1])=="--locked") CHECK(r==IAP2_PROVIDER_FAILED&&error==ERROR_SHARING_VIOLATION);
        else { CHECK(r==IAP2_OK&&s.s.data.count==1&&s.s.data.identity.ready);CHECK(pair_store_file_view_init(&s.view,&s.s,1)==IAP2_OK); }return 0;
    }
    CHECK(argc==3);auto v=load_vectors(argv[1],51);Temporary tmp(argv[2]);
    persistence(tmp,v);policy(tmp,v);journal_corruption(tmp,v);capacity(tmp,v);
#ifdef PAIR_STORE_TESTING
    creation_interruptions(tmp,v);
#endif
    enrollment_and_interruptions(tmp,v);tmp.cleanup();
    std::cout<<"PASS: real private Windows files, process lock/reopen, journal validation and enrolled encrypted control\n";
#ifdef PAIR_STORE_TESTING
    std::cout<<"PASS: initial creation and enrollment append interruption/uncertainty checks\n";
#else
    std::cout<<"PASS: production backend (no compiled fault hooks)\n";
#endif
    std::cout<<"Removed only newly created synthetic test files and their owned directories\n";return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<" Windows last error="<<GetLastError()<<'\n';return 1; } }
