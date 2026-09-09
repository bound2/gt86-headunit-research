/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _WIN32
#error This backend requires Windows; a target filesystem port is not supplied.
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include "pair_store_file.h"
typedef struct private_security {
    union { TOKEN_USER align;uint8_t bytes[256]; } token;
    union { uint64_t align;uint8_t bytes[256]; } acl;
    SECURITY_DESCRIPTOR descriptor;
    SECURITY_ATTRIBUTES attributes;
    PSID sid;
} private_security;
static void copy(void *d,const void *s,size_t n) { uint8_t *a=(uint8_t *)d;const uint8_t *b=(const uint8_t *)s;while(n--) *a++=*b++; }
static void set_error(uint32_t *out,DWORD error) { if(out) *out=(uint32_t)error; }
static int os_failure(uint32_t *out) { set_error(out,GetLastError());return IAP2_PROVIDER_FAILED; }
static HANDLE handle(uintptr_t h) { return (HANDLE)h; }
static int security_init(private_security *s,int directory,uint32_t *error) {
    HANDLE token=0;DWORD needed=0,saved;BYTE flags=directory?(OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE):0;
    pair_crypto_wipe(s,sizeof(*s));
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return os_failure(error);
    if(!GetTokenInformation(token,TokenUser,s->token.bytes,sizeof(s->token.bytes),&needed)) {
        saved=GetLastError();CloseHandle(token);set_error(error,saved);return IAP2_PROVIDER_FAILED;
    }
    CloseHandle(token);s->sid=((TOKEN_USER *)s->token.bytes)->User.Sid;
    if(!InitializeAcl((PACL)s->acl.bytes,sizeof(s->acl.bytes),ACL_REVISION)||
       !AddAccessAllowedAceEx((PACL)s->acl.bytes,ACL_REVISION,flags,FILE_ALL_ACCESS,s->sid)||
       !InitializeSecurityDescriptor(&s->descriptor,SECURITY_DESCRIPTOR_REVISION)||
       !SetSecurityDescriptorOwner(&s->descriptor,s->sid,FALSE)||
       !SetSecurityDescriptorDacl(&s->descriptor,TRUE,(PACL)s->acl.bytes,FALSE)||
       !SetSecurityDescriptorControl(&s->descriptor,SE_DACL_PROTECTED,SE_DACL_PROTECTED)) return os_failure(error);
    s->attributes.nLength=sizeof(s->attributes);s->attributes.lpSecurityDescriptor=&s->descriptor;s->attributes.bInheritHandle=FALSE;
    return IAP2_OK;
}
static int private_acl(HANDLE h,PSID user,int directory,uint32_t *error) {
    PSECURITY_DESCRIPTOR sd=0;PSID owner=0;PACL acl=0;SECURITY_DESCRIPTOR_CONTROL control=0;
    DWORD revision=0,r;ACCESS_ALLOWED_ACE *ace=0;int ok=0;
    r=GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,0,&acl,0,&sd);
    if(r!=ERROR_SUCCESS) { set_error(error,r);return IAP2_PROVIDER_FAILED; }
    if(owner&&EqualSid(owner,user)&&GetSecurityDescriptorControl(sd,&control,&revision)&&
       (control&SE_DACL_PROTECTED)&&(control&SE_DACL_PRESENT)&&acl&&acl->AceCount==1&&GetAce(acl,0,(void **)&ace)&&
       ace->Header.AceType==ACCESS_ALLOWED_ACE_TYPE&&ace->Header.AceFlags==(directory?(OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE):0)&&
       ace->Mask==FILE_ALL_ACCESS&&EqualSid((PSID)&ace->SidStart,user)) ok=1;
    LocalFree(sd);if(!ok) { set_error(error,ERROR_ACCESS_DENIED);return IAP2_AUTH_FAILED; }return IAP2_OK;
}
static int same_word(const WCHAR *p,size_t n,const char *word) {
    size_t i;for(i=0;i<n;++i) { WCHAR c=p[i];if(!word[i]) return 0;if(c>='a'&&c<='z') c-=32;if(c!=(WCHAR)word[i]) return 0; }return word[n]==0;
}
static int component(const WCHAR *p,size_t n) {
    size_t i,base=n;if(!n||p[n-1]=='.'||p[n-1]==' ') return 0;
    for(i=0;i<n;++i) if(p[i]=='.') { base=i;break; }
    while(base&&p[base-1]==' ') --base; /* Device aliases with pre-extension spaces. */
    if(same_word(p,base,"CON")||same_word(p,base,"PRN")||same_word(p,base,"AUX")||same_word(p,base,"NUL")||
       same_word(p,base,"CONIN$")||same_word(p,base,"CONOUT$")) return 0;
    if(base==4&&p[3]>='1'&&p[3]<='9'&&(same_word(p,3,"COM")||same_word(p,3,"LPT"))) return 0;
    return 1;
}
static int path_parse(const char *path,WCHAR out[PAIR_STORE_PATH_MAX],size_t *length) {
    size_t i,start=3,n=0;if(!path) return IAP2_ARGUMENT;
    while(n<PAIR_STORE_PATH_MAX&&path[n]) ++n;if(n<4||n>=PAIR_STORE_PATH_MAX) return IAP2_ARGUMENT;
    if(!((path[0]>='A'&&path[0]<='Z')||(path[0]>='a'&&path[0]<='z'))||path[1]!=':'||(path[2]!='\\'&&path[2]!='/')) return IAP2_ARGUMENT;
    for(i=0;i<n;++i) {
        unsigned char c=(unsigned char)path[i];if(c<32||c>126||c=='<'||c=='>'||c=='"'||c=='|'||c=='?'||c=='*'||(c==':'&&i!=1)) return IAP2_ARGUMENT;
        out[i]=(WCHAR)(c=='/'?'\\':c);
        if(i>=3&&out[i]=='\\') { if(!component(out+start,i-start)) return IAP2_ARGUMENT;start=i+1; }
    }
    if(!component(out+start,n-start)) return IAP2_ARGUMENT;out[n]=0;*length=n;return IAP2_OK;
}
static void handles_close(pair_store_file *s) {
    if(s->handle) { CloseHandle(handle(s->handle));s->handle=0; }
    while(s->ancestor_count) { --s->ancestor_count;CloseHandle(handle(s->ancestors[s->ancestor_count]));s->ancestors[s->ancestor_count]=0; }
}
static int directory_open(pair_store_file *s,const WCHAR *path,uint32_t *error) {
    HANDLE h;BY_HANDLE_FILE_INFORMATION info;
    if(s->ancestor_count==PAIR_STORE_ANCESTORS_MAX) return IAP2_NO_SPACE;
    h=CreateFileW(path,FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_EXISTING,
                  FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,0);
    if(h==INVALID_HANDLE_VALUE) return os_failure(error);
    if(!GetFileInformationByHandle(h,&info)) { DWORD e=GetLastError();CloseHandle(h);set_error(error,e);return IAP2_PROVIDER_FAILED; }
    if(!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)) {
        CloseHandle(h);set_error(error,ERROR_ACCESS_DENIED);return IAP2_AUTH_FAILED;
    }
    s->ancestors[s->ancestor_count++]=(uintptr_t)h;return IAP2_OK;
}
static int ancestors_open(pair_store_file *s,WCHAR *path,size_t n,uint32_t *error) {
    WCHAR saved;size_t i;DWORD flags=0;int r;
    saved=path[3];path[3]=0;
    if(GetDriveTypeW(path)!=DRIVE_FIXED) { path[3]=saved;return IAP2_UNSUPPORTED; }
    r=directory_open(s,path,error);path[3]=saved;if(r!=IAP2_OK) return r;
    if(!GetVolumeInformationByHandleW(handle(s->ancestors[0]),0,0,0,0,&flags,0,0)) return os_failure(error);
    if(!(flags&FILE_PERSISTENT_ACLS)) return IAP2_UNSUPPORTED;
    for(i=3;i<n;++i) if(path[i]=='\\') { path[i]=0;r=directory_open(s,path,error);path[i]='\\';if(r!=IAP2_OK) return r; }
    return IAP2_OK;
}
int pair_store_directory_create(const char *path,uint32_t *error) {
    pair_store_file tmp;private_security security;WCHAR wide[PAIR_STORE_PATH_MAX];size_t n=0;int r;
    set_error(error,0);r=path_parse(path,wide,&n);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(&tmp,sizeof(tmp));r=security_init(&security,1,error);if(r!=IAP2_OK) goto done;
    r=ancestors_open(&tmp,wide,n,error);if(r!=IAP2_OK) goto done;
    if(!CreateDirectoryW(wide,&security.attributes)) { r=os_failure(error);goto done; }
    r=directory_open(&tmp,wide,error);if(r==IAP2_OK) r=private_acl(handle(tmp.ancestors[tmp.ancestor_count-1]),security.sid,1,error);
done: handles_close(&tmp);pair_crypto_wipe(&security,sizeof(security));pair_crypto_wipe(&tmp,sizeof(tmp));return r;
}
static int file_validate(HANDLE h,PSID sid,uint32_t *error) {
    BY_HANDLE_FILE_INFORMATION info;
    if(GetFileType(h)!=FILE_TYPE_DISK) return IAP2_UNSUPPORTED;
    if(!GetFileInformationByHandle(h,&info)) return os_failure(error);
    if((info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||info.nNumberOfLinks!=1) {
        set_error(error,ERROR_ACCESS_DENIED);return IAP2_AUTH_FAILED;
    }
    return private_acl(h,sid,0,error);
}
static int seek(HANDLE h,uint64_t position,uint32_t *error) {
    LARGE_INTEGER p;p.QuadPart=(LONGLONG)position;if(!SetFilePointerEx(h,p,0,FILE_BEGIN)) return os_failure(error);return IAP2_OK;
}
static int write_all(HANDLE h,const uint8_t *p,DWORD n,uint32_t *error) {
    DWORD written=0;
    while(n) { if(!WriteFile(h,p,n,&written,0)) return os_failure(error);
        if(!written) { set_error(error,ERROR_WRITE_FAULT);return IAP2_PROVIDER_FAILED; }p+=written;n-=written; }
    return IAP2_OK;
}
static int fault(pair_store_file *s,unsigned point) {
#ifdef PAIR_STORE_TESTING
    return s->test_fault==point;
#else
    (void)s;(void)point;return 0;
#endif
}
static int write_snapshot(pair_store_file *s,const uint8_t *image,uint32_t *error) {
    int r;
    if(fault(s,1)) { set_error(error,ERROR_WRITE_FAULT);return PAIR_STORE_UNCERTAIN; }
    r=write_all(handle(s->handle),image,fault(s,2)?23u:PAIR_STORE_IMAGE_SIZE,error);
    if(r!=IAP2_OK) return PAIR_STORE_UNCERTAIN;
    if(fault(s,2)||fault(s,3)) { set_error(error,ERROR_WRITE_FAULT);return PAIR_STORE_UNCERTAIN; }
    if(!FlushFileBuffers(handle(s->handle))) { set_error(error,GetLastError());return PAIR_STORE_UNCERTAIN; }
    if(fault(s,4)) { set_error(error,ERROR_WRITE_FAULT);return PAIR_STORE_UNCERTAIN; }return IAP2_OK;
}
static int read_image(HANDLE h,uint8_t *p,uint32_t *error) {
    DWORD left=PAIR_STORE_IMAGE_SIZE,got=0;
    while(left) { if(!ReadFile(h,p,left,&got,0)) return os_failure(error);
        if(!got) return PAIR_STORE_CORRUPT;p+=got;left-=got; }
    return IAP2_OK;
}
static int journal_load(pair_store_file *s,uint32_t *error) {
    LARGE_INTEGER size;pair_store_data next;uint8_t image[PAIR_STORE_IMAGE_SIZE];uint32_t i,images;int r=PAIR_STORE_CORRUPT;
    pair_crypto_wipe(&next,sizeof(next));pair_crypto_wipe(image,sizeof(image));
    if(!GetFileSizeEx(handle(s->handle),&size)) { r=os_failure(error);goto done; }
    if(size.QuadPart<PAIR_STORE_IMAGE_SIZE||size.QuadPart>PAIR_STORE_MAX_FILE_SIZE||size.QuadPart%PAIR_STORE_IMAGE_SIZE) goto done;
    images=(uint32_t)(size.QuadPart/PAIR_STORE_IMAGE_SIZE);
    for(i=0;i<images;++i) {
        r=read_image(handle(s->handle),image,error);if(r!=IAP2_OK) goto done;
        r=pair_store_decode(&next,image,sizeof(image));if(r!=IAP2_OK) goto done;
        r=i?pair_store_successor(&s->data,&next):(next.count==0&&next.revision==1?IAP2_OK:PAIR_STORE_CORRUPT);
        if(r!=IAP2_OK) goto done;copy(&s->data,&next,sizeof(next));pair_store_clear(&next);
    }
    /* A complete previously unacknowledged authorized append may be recovered.
     * Never skip/truncate malformed tails; no acknowledgement before this flush. */
    if(!FlushFileBuffers(handle(s->handle))) { set_error(error,GetLastError());r=PAIR_STORE_UNCERTAIN; }
done: pair_store_clear(&next);pair_crypto_wipe(image,sizeof(image));return r;
}
static int start(pair_store_file *out,const char *path,const pair_store_data *initial,uint64_t gen,uint32_t *error) {
    pair_store_file tmp;private_security security;WCHAR wide[PAIR_STORE_PATH_MAX];uint8_t image[PAIR_STORE_IMAGE_SIZE];size_t n=0;HANDLE h;int r;
    set_error(error,0);
    if(!out||!gen||gen<=out->generation||(out->state!=PAIR_STORE_FILE_EMPTY&&out->state!=PAIR_STORE_FILE_CLOSED)) return IAP2_ARGUMENT;
    r=path_parse(path,wide,&n);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(&tmp,sizeof(tmp));pair_crypto_wipe(image,sizeof(image));pair_crypto_wipe(&security,sizeof(security));
    if(initial) {
        if(initial->count!=0||initial->revision!=1) { r=IAP2_ARGUMENT;goto done; }
        r=pair_store_encode(initial,image,sizeof(image));if(r!=IAP2_OK) goto done;
    }
    r=security_init(&security,0,error);if(r!=IAP2_OK) goto done;
    r=ancestors_open(&tmp,wide,n,error);if(r!=IAP2_OK) goto done;
    r=private_acl(handle(tmp.ancestors[tmp.ancestor_count-1]),security.sid,1,error);if(r!=IAP2_OK) goto done;
    h=CreateFileW(wide,GENERIC_READ|GENERIC_WRITE|READ_CONTROL,0,initial?&security.attributes:0,initial?CREATE_NEW:OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,0);
    if(h==INVALID_HANDLE_VALUE) { r=os_failure(error);goto done; }tmp.handle=(uintptr_t)h;
    r=file_validate(h,security.sid,error);if(r!=IAP2_OK) goto done;
    if(initial) {
#ifdef PAIR_STORE_TESTING
        tmp.test_fault=out->test_fault;
#endif
        r=write_snapshot(&tmp,image,error);if(r!=IAP2_OK) goto done;
        copy(&tmp.data,initial,sizeof(*initial));
    } else { r=journal_load(&tmp,error);if(r!=IAP2_OK) goto done; }
    tmp.generation=gen;tmp.state=PAIR_STORE_FILE_ACTIVE;copy(out,&tmp,sizeof(tmp));tmp.handle=0;tmp.ancestor_count=0;r=IAP2_OK;
done: handles_close(&tmp);pair_crypto_wipe(&tmp,sizeof(tmp));pair_crypto_wipe(image,sizeof(image));pair_crypto_wipe(&security,sizeof(security));return r;
}
int pair_store_file_create(pair_store_file *s,const char *p,const pair_store_data *initial,uint64_t gen,uint32_t *error) {
    if(!initial) { set_error(error,0);return IAP2_ARGUMENT; }return start(s,p,initial,gen,error);
}
int pair_store_file_open(pair_store_file *s,const char *p,uint64_t gen,uint32_t *error) { return start(s,p,0,gen,error); }
static int view_valid(const pair_store_file_view *v,int active) {
    if(!v||!v->store||!v->generation) return IAP2_ARGUMENT;
    if(v->generation!=v->store->generation) return IAP2_INVALID;
    if(v->store->state!=PAIR_STORE_FILE_ACTIVE&&(active||v->store->state!=PAIR_STORE_FILE_POISONED)) return PAIR_STORE_CLOSED;
    return IAP2_OK;
}
int pair_store_file_view_init(pair_store_file_view *v,pair_store_file *s,uint64_t gen) {
    pair_store_file_view tmp;int r;if(!v) return IAP2_ARGUMENT;tmp.store=s;tmp.generation=gen;r=view_valid(&tmp,1);if(r==IAP2_OK) *v=tmp;return r;
}
const pair_identity *pair_store_file_identity(const pair_store_file_view *v) { return view_valid(v,1)==IAP2_OK?&v->store->data.identity:0; }
int pair_store_file_lookup(void *context,const uint8_t *id,size_t n,uint8_t pk[32]) {
    pair_store_file_view *v=(pair_store_file_view *)context;int r;if(pk) pair_crypto_wipe(pk,32);if(!pk) return IAP2_ARGUMENT;
    r=view_valid(v,1);return r==IAP2_OK?pair_store_lookup(&v->store->data,id,n,pk):r;
}
int pair_store_file_close(pair_store_file_view v) {
    pair_store_file *s=v.store;uint64_t gen;int r=view_valid(&v,0);if(r!=IAP2_OK) return r;
    gen=s->generation;handles_close(s);pair_crypto_wipe(s,sizeof(*s));s->generation=gen;s->state=PAIR_STORE_FILE_CLOSED;return IAP2_OK;
}
int pair_store_file_bind(pair_store_file_binding *b,pair_store_file_view v,uint64_t gen,uint64_t authority) {
    int r;if(!b||!gen||!authority) return IAP2_ARGUMENT;r=view_valid(&v,1);if(r!=IAP2_OK) return r;
    pair_crypto_wipe(b,sizeof(*b));b->view=v;b->enrollment_generation=gen;b->authorization=authority;return IAP2_OK;
}
static int poison(pair_store_file *s,uint32_t error) { s->state=PAIR_STORE_FILE_POISONED;s->system_error=error;return PAIR_STORE_UNCERTAIN; }
#ifdef PAIR_STORE_TESTING
int pair_store_file_test_fault(pair_store_file_view v,unsigned point) {
    int r=view_valid(&v,1);if(r!=IAP2_OK) return r;if(point>4) return IAP2_ARGUMENT;v.store->test_fault=point;return IAP2_OK;
}
int pair_store_file_test_initial_fault(pair_store_file *s,unsigned point) {
    if(!s||point>4||(s->state!=PAIR_STORE_FILE_EMPTY&&s->state!=PAIR_STORE_FILE_CLOSED)) return IAP2_ARGUMENT;
    s->test_fault=point;return IAP2_OK;
}
#endif
int pair_store_file_commit(void *context,uint64_t gen,uint64_t authority,const uint8_t *id,size_t n,const uint8_t pk[32]) {
    pair_store_file_binding *b=(pair_store_file_binding *)context;pair_store_file *s;pair_store_data next;
    uint8_t image[PAIR_STORE_IMAGE_SIZE];uint32_t error=0;LARGE_INTEGER size;int r;
    if(!b||!gen||!authority||!pk||!id||!n||n>PAIR_ID_MAX) return IAP2_ARGUMENT;
    if(b->enrollment_generation!=gen||b->authorization!=authority||b->used) return IAP2_INVALID;
    r=view_valid(&b->view,1);if(r!=IAP2_OK) return r;s=b->view.store;
    /* Validate on a secret-bearing temporary, never mutate the live identity
     * borrowed by sessions, and never expose an unacknowledged new mapping. */
    copy(&next,&s->data,sizeof(next));pair_crypto_wipe(image,sizeof(image));r=pair_store_add(&next,id,n,pk);
    if(r==IAP2_ARGUMENT) goto done;b->used=1;
    if(r==IAP2_END) { r=IAP2_OK;goto done; }if(r!=IAP2_OK) goto done;
    r=pair_store_encode(&next,image,sizeof(image));if(r!=IAP2_OK) goto done;
    if(!GetFileSizeEx(handle(s->handle),&size)) { r=poison(s,GetLastError());goto done; }
    if(size.QuadPart!=(LONGLONG)(s->data.revision*PAIR_STORE_IMAGE_SIZE)) { r=poison(s,ERROR_FILE_CORRUPT);goto done; }
    r=seek(handle(s->handle),(uint64_t)size.QuadPart,&error);if(r!=IAP2_OK) { r=poison(s,error);goto done; }
    r=write_snapshot(s,image,&error);if(r!=IAP2_OK) { r=poison(s,error);goto done; }
    copy(&s->data.controllers[s->data.count],&next.controllers[s->data.count],sizeof(pair_store_entry));
    s->data.count=next.count;s->data.revision=next.revision;r=IAP2_OK;
done: pair_store_clear(&next);pair_crypto_wipe(image,sizeof(image));return r;
}
