// tsf_text_service.h
// Complete TSF (Text Services Framework) implementation for Witnessd
//
// This header defines the COM interfaces needed for a fully-featured
// TSF text input processor with keystroke monitoring capabilities.

#ifndef WITNESSD_TSF_TEXT_SERVICE_H
#define WITNESSD_TSF_TEXT_SERVICE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msctf.h>
#include <ctffunc.h>
#include <olectl.h>
#include <atomic>
#include <string>
#include <vector>
#include <mutex>
#include <queue>

// ============================================================================
// GUIDs
// ============================================================================

// CLSID for Witnessd TSF Text Service
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(CLSID_WitnessdTextService,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

// GUID for Witnessd language profile
// {B2C3D4E5-F678-90AB-CDEF-123456789012}
DEFINE_GUID(GUID_WitnessdProfile,
    0xb2c3d4e5, 0xf678, 0x90ab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12);

// GUID for compartment (enabling/disabling)
// {C3D4E5F6-7890-ABCD-EF12-3456789012AB}
DEFINE_GUID(GUID_WitnessdCompartment,
    0xc3d4e5f6, 0x7890, 0xabcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xab);

// ============================================================================
// Forward declarations for Go callbacks
// ============================================================================

extern "C" {
    int WitnessdInit();
    void WitnessdShutdown();
    int WitnessdStartSession(char* appID, char* docID);
    char* WitnessdEndSession();
    int64_t WitnessdOnKeyDown(uint16_t vkCode, int32_t charCode);
    void WitnessdOnKeyUp(uint16_t vkCode);
    void WitnessdOnTextCommit(char* text);
    void WitnessdOnTextDelete(int count);
    void WitnessdOnFocusChange(char* appName, char* docTitle);
    void WitnessdOnCompositionStart();
    void WitnessdOnCompositionEnd(char* text);
    int WitnessdGetSampleCount();
    int WitnessdHasActiveSession();
    void WitnessdFreeString(char* s);
}

// ============================================================================
// Keystroke Event Structure
// ============================================================================

struct KeystrokeEvent {
    WPARAM wParam;
    LPARAM lParam;
    UINT scanCode;
    bool isKeyDown;
    bool isExtended;
    bool isAltDown;
    DWORD time;
    int64_t timestamp_ns;
};

// ============================================================================
// WitnessdTextService Class
// ============================================================================

// Implements all necessary TSF interfaces for a text input processor:
// - ITfTextInputProcessorEx: Core TIP interface
// - ITfKeyEventSink: Keystroke handling
// - ITfThreadMgrEventSink: Thread/focus events
// - ITfTextEditSink: Text edit notifications
// - ITfCompositionSink: Composition events
// - ITfDisplayAttributeProvider: Display attributes (minimal)

class WitnessdTextService :
    public ITfTextInputProcessorEx,
    public ITfKeyEventSink,
    public ITfThreadMgrEventSink,
    public ITfTextEditSink,
    public ITfCompositionSink,
    public ITfDisplayAttributeProvider
{
public:
    WitnessdTextService();
    virtual ~WitnessdTextService();

    // ========================================================================
    // IUnknown
    // ========================================================================
    STDMETHODIMP QueryInterface(REFIID riid, void** ppvObject) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // ========================================================================
    // ITfTextInputProcessor
    // ========================================================================
    STDMETHODIMP Activate(ITfThreadMgr* pThreadMgr, TfClientId tfClientId) override;
    STDMETHODIMP Deactivate() override;

    // ========================================================================
    // ITfTextInputProcessorEx
    // ========================================================================
    STDMETHODIMP ActivateEx(ITfThreadMgr* pThreadMgr, TfClientId tfClientId, DWORD dwFlags) override;

    // ========================================================================
    // ITfKeyEventSink
    // ========================================================================
    STDMETHODIMP OnSetFocus(BOOL fForeground) override;
    STDMETHODIMP OnTestKeyDown(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) override;
    STDMETHODIMP OnTestKeyUp(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) override;
    STDMETHODIMP OnKeyDown(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) override;
    STDMETHODIMP OnKeyUp(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) override;
    STDMETHODIMP OnPreservedKey(ITfContext* pContext, REFGUID rguid, BOOL* pfEaten) override;

    // ========================================================================
    // ITfThreadMgrEventSink
    // ========================================================================
    STDMETHODIMP OnInitDocumentMgr(ITfDocumentMgr* pDocMgr) override;
    STDMETHODIMP OnUninitDocumentMgr(ITfDocumentMgr* pDocMgr) override;
    STDMETHODIMP OnSetFocus(ITfDocumentMgr* pDocMgrFocus, ITfDocumentMgr* pDocMgrPrevFocus) override;
    STDMETHODIMP OnPushContext(ITfContext* pContext) override;
    STDMETHODIMP OnPopContext(ITfContext* pContext) override;

    // ========================================================================
    // ITfTextEditSink
    // ========================================================================
    STDMETHODIMP OnEndEdit(ITfContext* pContext, TfEditCookie ecReadOnly, ITfEditRecord* pEditRecord) override;

    // ========================================================================
    // ITfCompositionSink
    // ========================================================================
    STDMETHODIMP OnCompositionTerminated(TfEditCookie ecWrite, ITfComposition* pComposition) override;

    // ========================================================================
    // ITfDisplayAttributeProvider
    // ========================================================================
    STDMETHODIMP EnumDisplayAttributeInfo(IEnumTfDisplayAttributeInfo** ppEnum) override;
    STDMETHODIMP GetDisplayAttributeInfo(REFGUID guid, ITfDisplayAttributeInfo** ppInfo) override;

    // ========================================================================
    // Class Factory Support
    // ========================================================================
    static HRESULT CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject);

    // ========================================================================
    // Public Methods
    // ========================================================================
    TfClientId GetClientId() const { return clientId_; }
    bool IsActivated() const { return isActivated_; }
    bool IsEnabled() const { return isEnabled_; }
    void SetEnabled(bool enabled) { isEnabled_ = enabled; }

private:
    // Reference counting
    std::atomic<LONG> refCount_;

    // TSF state
    ITfThreadMgr* threadMgr_;
    TfClientId clientId_;
    DWORD activateFlags_;

    // Sink interfaces
    ITfKeystrokeMgr* keystrokeMgr_;
    DWORD threadMgrEventSinkCookie_;
    DWORD textEditSinkCookie_;
    DWORD compositionSinkCookie_;

    // Current context
    ITfDocumentMgr* currentDocMgr_;
    ITfContext* currentContext_;
    ITfComposition* currentComposition_;

    // State flags
    bool isActivated_;
    bool isEnabled_;
    bool isComposing_;

    // Focus tracking
    std::wstring currentAppPath_;
    std::wstring currentWindowTitle_;
    HWND currentFocusWindow_;

    // Keystroke queue for async processing
    std::mutex keystrokeQueueMutex_;
    std::queue<KeystrokeEvent> keystrokeQueue_;

    // Private methods
    HRESULT SetupSinks();
    void CleanupSinks();
    HRESULT SetupKeystrokeSink();
    void CleanupKeystrokeSink();
    HRESULT SetupThreadMgrEventSink();
    void CleanupThreadMgrEventSink();
    HRESULT SetupTextEditSink(ITfContext* pContext);
    void CleanupTextEditSink(ITfContext* pContext);

    int VKToChar(WPARAM vk, LPARAM lParam);
    void UpdateFocusInfo();
    std::string WideToUTF8(const std::wstring& wide);
    void ProcessKeystroke(const KeystrokeEvent& event);
    void NotifyFocusChange();
};

// ============================================================================
// WitnessdClassFactory Class
// ============================================================================

class WitnessdClassFactory : public IClassFactory
{
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

// ============================================================================
// Registration Functions
// ============================================================================

HRESULT RegisterTextService();
HRESULT UnregisterTextService();
HRESULT RegisterCOMServer(HINSTANCE hInstance);
HRESULT UnregisterCOMServer();

// ============================================================================
// DLL Exports
// ============================================================================

extern "C" {
    BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    HRESULT WINAPI DllCanUnloadNow();
    HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppvObject);
    HRESULT WINAPI DllRegisterServer();
    HRESULT WINAPI DllUnregisterServer();
}

// ============================================================================
// Global State
// ============================================================================

extern HINSTANCE g_hInstance;
extern std::atomic<LONG> g_dllRefCount;

#endif // WITNESSD_TSF_TEXT_SERVICE_H
