// witnessd_tsf.h
// Windows TSF (Text Services Framework) implementation for Witnessd
//
// This header defines the COM interfaces needed for a TSF text input processor.

#ifndef WITNESSD_TSF_H
#define WITNESSD_TSF_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msctf.h>
#include <atomic>

// CLSID for Witnessd TSF
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(CLSID_WitnessdTSF,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

// GUID for Witnessd language profile
// {B2C3D4E5-F678-90AB-CDEF-123456789012}
DEFINE_GUID(GUID_WitnessdProfile,
    0xb2c3d4e5, 0xf678, 0x90ab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12);

// Forward declarations from Go
extern "C" {
    int WitnessdInit();
    void WitnessdShutdown();
    int WitnessdStartSession(char* appID, char* docID);
    char* WitnessdEndSession();
    int64_t WitnessdOnKeyDown(uint16_t vkCode, int32_t charCode);
    void WitnessdOnTextCommit(char* text);
    void WitnessdOnTextDelete(int count);
    int WitnessdGetSampleCount();
    int WitnessdHasActiveSession();
    void WitnessdFreeString(char* s);
}

// WitnessdTextService implements ITfTextInputProcessor
class WitnessdTextService : public ITfTextInputProcessorEx,
                            public ITfKeyEventSink,
                            public ITfDisplayAttributeProvider {
public:
    WitnessdTextService();
    virtual ~WitnessdTextService();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppvObject) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // ITfTextInputProcessor
    STDMETHODIMP Activate(ITfThreadMgr* pThreadMgr, TfClientId tfClientId) override;
    STDMETHODIMP Deactivate() override;

    // ITfTextInputProcessorEx
    STDMETHODIMP ActivateEx(ITfThreadMgr* pThreadMgr, TfClientId tfClientId, DWORD dwFlags) override;

    // ITfKeyEventSink
    STDMETHODIMP OnSetFocus(BOOL fForeground) override;
    STDMETHODIMP OnTestKeyDown(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) override;
    STDMETHODIMP OnTestKeyUp(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) override;
    STDMETHODIMP OnKeyDown(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) override;
    STDMETHODIMP OnKeyUp(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) override;
    STDMETHODIMP OnPreservedKey(ITfContext* pContext, REFGUID rguid, BOOL* pfEaten) override;

    // ITfDisplayAttributeProvider
    STDMETHODIMP EnumDisplayAttributeInfo(IEnumTfDisplayAttributeInfo** ppEnum) override;
    STDMETHODIMP GetDisplayAttributeInfo(REFGUID guid, ITfDisplayAttributeInfo** ppInfo) override;

    // Class factory creates instances
    static HRESULT CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject);

private:
    std::atomic<LONG> refCount_;
    ITfThreadMgr* threadMgr_;
    TfClientId clientId_;
    ITfKeystrokeMgr* keystrokeMgr_;
    DWORD keystrokeSinkCookie_;
    bool isActivated_;

    HRESULT SetupKeySinks();
    void CleanupKeySinks();
    int VKToChar(WPARAM vk, LPARAM lParam);
};

// Class factory for WitnessdTextService
class WitnessdClassFactory : public IClassFactory {
public:
    WitnessdClassFactory();
    virtual ~WitnessdClassFactory();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppvObject) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // IClassFactory
    STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override;
    STDMETHODIMP LockServer(BOOL fLock) override;

private:
    std::atomic<LONG> refCount_;
};

// DLL exports
extern "C" {
    BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    HRESULT WINAPI DllCanUnloadNow();
    HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppvObject);
    HRESULT WINAPI DllRegisterServer();
    HRESULT WINAPI DllUnregisterServer();
}

// Global state
extern HINSTANCE g_hInstance;
extern std::atomic<LONG> g_dllRefCount;

#endif // WITNESSD_TSF_H
