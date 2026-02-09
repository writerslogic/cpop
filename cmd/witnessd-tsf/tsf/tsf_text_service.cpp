// tsf_text_service.cpp
// Complete TSF (Text Services Framework) implementation for Witnessd

#include "tsf_text_service.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <psapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// Global State
// ============================================================================

HINSTANCE g_hInstance = nullptr;
std::atomic<LONG> g_dllRefCount{0};
static WitnessdClassFactory* g_classFactory = nullptr;

// Performance counter for timestamps
static LARGE_INTEGER g_perfFreq;
static bool g_perfFreqInit = false;

static int64_t GetTimestampNanos() {
    if (!g_perfFreqInit) {
        QueryPerformanceFrequency(&g_perfFreq);
        g_perfFreqInit = true;
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (int64_t)((double)counter.QuadPart / (double)g_perfFreq.QuadPart * 1e9);
}

// ============================================================================
// DLL Entry Points
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        WitnessdInit();
        break;

    case DLL_PROCESS_DETACH:
        WitnessdShutdown();
        if (g_classFactory != nullptr) {
            delete g_classFactory;
            g_classFactory = nullptr;
        }
        break;
    }
    return TRUE;
}

HRESULT WINAPI DllCanUnloadNow() {
    return (g_dllRefCount == 0) ? S_OK : S_FALSE;
}

HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppvObject) {
    if (ppvObject == nullptr) {
        return E_INVALIDARG;
    }
    *ppvObject = nullptr;

    if (!IsEqualCLSID(rclsid, CLSID_WitnessdTextService)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    if (g_classFactory == nullptr) {
        g_classFactory = new WitnessdClassFactory();
    }

    return g_classFactory->QueryInterface(riid, ppvObject);
}

HRESULT WINAPI DllRegisterServer() {
    HRESULT hr = RegisterCOMServer(g_hInstance);
    if (FAILED(hr)) {
        return hr;
    }

    hr = RegisterTextService();
    if (FAILED(hr)) {
        UnregisterCOMServer();
        return hr;
    }

    return S_OK;
}

HRESULT WINAPI DllUnregisterServer() {
    UnregisterTextService();
    UnregisterCOMServer();
    return S_OK;
}

// ============================================================================
// COM Server Registration
// ============================================================================

HRESULT RegisterCOMServer(HINSTANCE hInstance) {
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(hInstance, dllPath, MAX_PATH)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Get CLSID string
    wchar_t clsidStr[64];
    StringFromGUID2(CLSID_WitnessdTextService, clsidStr, 64);

    // Create CLSID key
    std::wstring keyPath = L"CLSID\\";
    keyPath += clsidStr;

    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, keyPath.c_str(), 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
        return E_FAIL;
    }

    RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)L"Witnessd Text Service",
                   (DWORD)((wcslen(L"Witnessd Text Service") + 1) * sizeof(wchar_t)));

    // Create InProcServer32 subkey
    std::wstring inprocPath = keyPath + L"\\InProcServer32";
    HKEY hInprocKey;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, inprocPath.c_str(), 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hInprocKey, nullptr) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return E_FAIL;
    }

    RegSetValueExW(hInprocKey, nullptr, 0, REG_SZ, (const BYTE*)dllPath,
                   (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
    RegSetValueExW(hInprocKey, L"ThreadingModel", 0, REG_SZ,
                   (const BYTE*)L"Apartment",
                   (DWORD)((wcslen(L"Apartment") + 1) * sizeof(wchar_t)));

    RegCloseKey(hInprocKey);
    RegCloseKey(hKey);

    return S_OK;
}

HRESULT UnregisterCOMServer() {
    wchar_t clsidStr[64];
    StringFromGUID2(CLSID_WitnessdTextService, clsidStr, 64);

    std::wstring keyPath = L"CLSID\\";
    keyPath += clsidStr;

    SHDeleteKeyW(HKEY_CLASSES_ROOT, keyPath.c_str());
    return S_OK;
}

// ============================================================================
// TSF Registration
// ============================================================================

HRESULT RegisterTextService() {
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_hInstance, dllPath, MAX_PATH)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Register with ITfInputProcessorProfiles
    ITfInputProcessorProfiles* pProfiles = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_ITfInputProcessorProfiles,
                                  (void**)&pProfiles);
    if (FAILED(hr)) {
        return hr;
    }

    // Register the text service
    hr = pProfiles->Register(CLSID_WitnessdTextService);
    if (FAILED(hr)) {
        pProfiles->Release();
        return hr;
    }

    // Add language profile
    hr = pProfiles->AddLanguageProfile(
        CLSID_WitnessdTextService,
        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        GUID_WitnessdProfile,
        L"Witnessd Authorship Witness",
        -1,  // Description string resource ID (-1 for static string)
        dllPath,
        0,   // Icon index
        0    // Ordinal
    );

    pProfiles->Release();

    if (FAILED(hr)) {
        return hr;
    }

    // Register as a TIP keyboard
    ITfCategoryMgr* pCategoryMgr = nullptr;
    hr = CoCreateInstance(CLSID_TF_CategoryMgr, nullptr,
                          CLSCTX_INPROC_SERVER, IID_ITfCategoryMgr,
                          (void**)&pCategoryMgr);

    if (SUCCEEDED(hr)) {
        pCategoryMgr->RegisterCategory(
            CLSID_WitnessdTextService,
            GUID_TFCAT_TIP_KEYBOARD,
            CLSID_WitnessdTextService
        );
        pCategoryMgr->Release();
    }

    return S_OK;
}

HRESULT UnregisterTextService() {
    // Unregister from ITfInputProcessorProfiles
    ITfInputProcessorProfiles* pProfiles = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_ITfInputProcessorProfiles,
                                  (void**)&pProfiles);
    if (SUCCEEDED(hr)) {
        pProfiles->Unregister(CLSID_WitnessdTextService);
        pProfiles->Release();
    }

    // Unregister category
    ITfCategoryMgr* pCategoryMgr = nullptr;
    hr = CoCreateInstance(CLSID_TF_CategoryMgr, nullptr,
                          CLSCTX_INPROC_SERVER, IID_ITfCategoryMgr,
                          (void**)&pCategoryMgr);
    if (SUCCEEDED(hr)) {
        pCategoryMgr->UnregisterCategory(
            CLSID_WitnessdTextService,
            GUID_TFCAT_TIP_KEYBOARD,
            CLSID_WitnessdTextService
        );
        pCategoryMgr->Release();
    }

    return S_OK;
}

// ============================================================================
// WitnessdClassFactory Implementation
// ============================================================================

WitnessdClassFactory::WitnessdClassFactory() : refCount_(1) {
    g_dllRefCount++;
}

WitnessdClassFactory::~WitnessdClassFactory() {
    g_dllRefCount--;
}

STDMETHODIMP WitnessdClassFactory::QueryInterface(REFIID riid, void** ppvObject) {
    if (ppvObject == nullptr) {
        return E_INVALIDARG;
    }

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
        *ppvObject = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }

    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) WitnessdClassFactory::AddRef() {
    return ++refCount_;
}

STDMETHODIMP_(ULONG) WitnessdClassFactory::Release() {
    LONG count = --refCount_;
    if (count == 0) {
        delete this;
    }
    return count;
}

STDMETHODIMP WitnessdClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) {
    if (pUnkOuter != nullptr) {
        return CLASS_E_NOAGGREGATION;
    }
    return WitnessdTextService::CreateInstance(pUnkOuter, riid, ppvObject);
}

STDMETHODIMP WitnessdClassFactory::LockServer(BOOL fLock) {
    if (fLock) {
        g_dllRefCount++;
    } else {
        g_dllRefCount--;
    }
    return S_OK;
}

// ============================================================================
// WitnessdTextService Implementation
// ============================================================================

WitnessdTextService::WitnessdTextService()
    : refCount_(1),
      threadMgr_(nullptr),
      clientId_(0),
      activateFlags_(0),
      keystrokeMgr_(nullptr),
      threadMgrEventSinkCookie_(TF_INVALID_COOKIE),
      textEditSinkCookie_(TF_INVALID_COOKIE),
      compositionSinkCookie_(TF_INVALID_COOKIE),
      currentDocMgr_(nullptr),
      currentContext_(nullptr),
      currentComposition_(nullptr),
      isActivated_(false),
      isEnabled_(true),
      isComposing_(false),
      currentFocusWindow_(nullptr)
{
    g_dllRefCount++;
}

WitnessdTextService::~WitnessdTextService() {
    g_dllRefCount--;
}

HRESULT WitnessdTextService::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) {
    if (ppvObject == nullptr) {
        return E_INVALIDARG;
    }
    *ppvObject = nullptr;

    if (pUnkOuter != nullptr) {
        return CLASS_E_NOAGGREGATION;
    }

    WitnessdTextService* pService = new (std::nothrow) WitnessdTextService();
    if (pService == nullptr) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pService->QueryInterface(riid, ppvObject);
    pService->Release();
    return hr;
}

// ============================================================================
// IUnknown Implementation
// ============================================================================

STDMETHODIMP WitnessdTextService::QueryInterface(REFIID riid, void** ppvObject) {
    if (ppvObject == nullptr) {
        return E_INVALIDARG;
    }

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ITfTextInputProcessor) ||
        IsEqualIID(riid, IID_ITfTextInputProcessorEx)) {
        *ppvObject = static_cast<ITfTextInputProcessorEx*>(this);
    }
    else if (IsEqualIID(riid, IID_ITfKeyEventSink)) {
        *ppvObject = static_cast<ITfKeyEventSink*>(this);
    }
    else if (IsEqualIID(riid, IID_ITfThreadMgrEventSink)) {
        *ppvObject = static_cast<ITfThreadMgrEventSink*>(this);
    }
    else if (IsEqualIID(riid, IID_ITfTextEditSink)) {
        *ppvObject = static_cast<ITfTextEditSink*>(this);
    }
    else if (IsEqualIID(riid, IID_ITfCompositionSink)) {
        *ppvObject = static_cast<ITfCompositionSink*>(this);
    }
    else if (IsEqualIID(riid, IID_ITfDisplayAttributeProvider)) {
        *ppvObject = static_cast<ITfDisplayAttributeProvider*>(this);
    }
    else {
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) WitnessdTextService::AddRef() {
    return ++refCount_;
}

STDMETHODIMP_(ULONG) WitnessdTextService::Release() {
    LONG count = --refCount_;
    if (count == 0) {
        delete this;
    }
    return count;
}

// ============================================================================
// ITfTextInputProcessor Implementation
// ============================================================================

STDMETHODIMP WitnessdTextService::Activate(ITfThreadMgr* pThreadMgr, TfClientId tfClientId) {
    return ActivateEx(pThreadMgr, tfClientId, 0);
}

STDMETHODIMP WitnessdTextService::Deactivate() {
    if (!isActivated_) {
        return S_OK;
    }

    // End any active session
    if (WitnessdHasActiveSession()) {
        char* evidence = WitnessdEndSession();
        if (evidence != nullptr) {
            WitnessdFreeString(evidence);
        }
    }

    // Cleanup sinks
    CleanupSinks();

    // Release thread manager
    if (threadMgr_ != nullptr) {
        threadMgr_->Release();
        threadMgr_ = nullptr;
    }

    clientId_ = 0;
    isActivated_ = false;

    return S_OK;
}

STDMETHODIMP WitnessdTextService::ActivateEx(ITfThreadMgr* pThreadMgr, TfClientId tfClientId, DWORD dwFlags) {
    if (isActivated_) {
        return S_OK;
    }

    threadMgr_ = pThreadMgr;
    threadMgr_->AddRef();
    clientId_ = tfClientId;
    activateFlags_ = dwFlags;

    // Setup all sinks
    HRESULT hr = SetupSinks();
    if (FAILED(hr)) {
        Deactivate();
        return hr;
    }

    // Update focus info and start session
    UpdateFocusInfo();
    std::string appId = WideToUTF8(currentAppPath_);
    std::string docId = WideToUTF8(currentWindowTitle_);
    if (appId.empty()) appId = "windows.tsf";
    if (docId.empty()) docId = "default";

    WitnessdStartSession(const_cast<char*>(appId.c_str()),
                         const_cast<char*>(docId.c_str()));

    isActivated_ = true;
    return S_OK;
}

// ============================================================================
// IPC Client (Named Pipe)
// ============================================================================

static HANDLE g_hPipe = INVALID_HANDLE_VALUE;

static void ConnectPipe() {
    if (g_hPipe != INVALID_HANDLE_VALUE) return;

    wchar_t username[256];
    DWORD len = 256;
    GetUserNameW(username, &len);

    wchar_t pipeName[512];
    StringCbPrintfW(pipeName, sizeof(pipeName), L"\\\\.\\pipe\\witnessd-%s-tsf-ipc", username);

    // Try to connect
    g_hPipe = CreateFileW(
        pipeName,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
}

static void DisconnectPipe() {
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}

static void WritePipe(uint16_t vkCode, uint16_t scanCode, uint32_t flags, int64_t timestamp, bool isDown) {
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        ConnectPipe();
        if (g_hPipe == INVALID_HANDLE_VALUE) return;
    }

    // Simple binary protocol:
    // [8 bytes timestamp] [2 bytes vk] [2 bytes scan] [4 bytes flags] [1 byte isDown]
    // Total 17 bytes
    #pragma pack(push, 1)
    struct {
        int64_t timestamp;
        uint16_t vkCode;
        uint16_t scanCode;
        uint32_t flags;
        uint8_t isDown;
    } msg;
    #pragma pack(pop)

    msg.timestamp = timestamp;
    msg.vkCode = vkCode;
    msg.scanCode = scanCode;
    msg.flags = flags;
    msg.isDown = isDown ? 1 : 0;

    DWORD written;
    BOOL success = WriteFile(g_hPipe, &msg, sizeof(msg), &written, NULL);
    
    if (!success) {
        DisconnectPipe(); // Reconnect next time
    }
}

// ============================================================================
// ITfKeyEventSink Implementation
// ============================================================================

STDMETHODIMP WitnessdTextService::OnSetFocus(BOOL fForeground) {
    (void)fForeground;
    UpdateFocusInfo();
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnTestKeyDown(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) {
    (void)pContext;
    (void)wParam;
    (void)lParam;
    *pfEaten = FALSE;  // Never eat keys - transparent monitoring
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnTestKeyUp(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) {
    (void)pContext;
    (void)wParam;
    (void)lParam;
    *pfEaten = FALSE;
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnKeyDown(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) {
    (void)pContext;
    *pfEaten = FALSE;  // Pass through

    if (!isEnabled_) {
        return S_OK;
    }

    // Record keystroke timing
    int64_t timestamp = GetTimestampNanos();
    
    // Write to named pipe
    WritePipe((uint16_t)wParam, (uint16_t)((lParam >> 16) & 0xFF), (uint32_t)lParam, timestamp, true);

    // Get character from virtual key
    int charCode = VKToChar(wParam, lParam);

    // Process through witnessd engine (Go callback)
    WitnessdOnKeyDown((uint16_t)wParam, (int32_t)charCode);

    // Record text commit for printable characters
    if (charCode >= 0x20 && charCode <= 0x7E) {
        char buf[2] = { (char)charCode, 0 };
        WitnessdOnTextCommit(buf);
    }

    // Handle backspace
    if (wParam == VK_BACK) {
        WitnessdOnTextDelete(1);
    }

    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnKeyUp(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) {
    (void)pContext;
    (void)wParam;
    (void)lParam;
    *pfEaten = FALSE;
    
    if (!isEnabled_) {
        return S_OK;
    }

    // Record keystroke timing
    int64_t timestamp = GetTimestampNanos();
    
    // Write to named pipe
    WritePipe((uint16_t)wParam, (uint16_t)((lParam >> 16) & 0xFF), (uint32_t)lParam, timestamp, false);

    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnPreservedKey(ITfContext* pContext, REFGUID rguid, BOOL* pfEaten) {
    (void)pContext;
    (void)rguid;
    *pfEaten = FALSE;
    return S_OK;
}

// ============================================================================
// ITfThreadMgrEventSink Implementation
// ============================================================================

STDMETHODIMP WitnessdTextService::OnInitDocumentMgr(ITfDocumentMgr* pDocMgr) {
    (void)pDocMgr;
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnUninitDocumentMgr(ITfDocumentMgr* pDocMgr) {
    (void)pDocMgr;
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnSetFocus(ITfDocumentMgr* pDocMgrFocus, ITfDocumentMgr* pDocMgrPrevFocus) {
    // Clean up previous context
    if (currentContext_ != nullptr) {
        CleanupTextEditSink(currentContext_);
        currentContext_->Release();
        currentContext_ = nullptr;
    }

    if (currentDocMgr_ != nullptr) {
        currentDocMgr_->Release();
        currentDocMgr_ = nullptr;
    }

    (void)pDocMgrPrevFocus;

    // Track new focus
    if (pDocMgrFocus != nullptr) {
        currentDocMgr_ = pDocMgrFocus;
        currentDocMgr_->AddRef();

        // Get the top context
        if (SUCCEEDED(pDocMgrFocus->GetTop(&currentContext_)) && currentContext_ != nullptr) {
            SetupTextEditSink(currentContext_);
        }
    }

    // Update focus info and notify
    UpdateFocusInfo();
    NotifyFocusChange();

    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnPushContext(ITfContext* pContext) {
    (void)pContext;
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnPopContext(ITfContext* pContext) {
    (void)pContext;
    return S_OK;
}

// ============================================================================
// ITfTextEditSink Implementation
// ============================================================================

STDMETHODIMP WitnessdTextService::OnEndEdit(ITfContext* pContext, TfEditCookie ecReadOnly, ITfEditRecord* pEditRecord) {
    (void)pContext;
    (void)ecReadOnly;
    (void)pEditRecord;

    // This is called when text editing ends in the context
    // We could use this to track document changes more accurately

    return S_OK;
}

// ============================================================================
// ITfCompositionSink Implementation
// ============================================================================

STDMETHODIMP WitnessdTextService::OnCompositionTerminated(TfEditCookie ecWrite, ITfComposition* pComposition) {
    (void)ecWrite;

    if (pComposition == currentComposition_) {
        currentComposition_->Release();
        currentComposition_ = nullptr;
        isComposing_ = false;

        // Could extract the final composed text here
        WitnessdOnCompositionEnd(const_cast<char*>(""));
    }

    return S_OK;
}

// ============================================================================
// ITfDisplayAttributeProvider Implementation
// ============================================================================

STDMETHODIMP WitnessdTextService::EnumDisplayAttributeInfo(IEnumTfDisplayAttributeInfo** ppEnum) {
    if (ppEnum == nullptr) {
        return E_INVALIDARG;
    }
    *ppEnum = nullptr;
    return E_NOTIMPL;  // We don't provide display attributes
}

STDMETHODIMP WitnessdTextService::GetDisplayAttributeInfo(REFGUID guid, ITfDisplayAttributeInfo** ppInfo) {
    (void)guid;
    if (ppInfo == nullptr) {
        return E_INVALIDARG;
    }
    *ppInfo = nullptr;
    return E_NOTIMPL;
}

// ============================================================================
// Private Methods
// ============================================================================

HRESULT WitnessdTextService::SetupSinks() {
    HRESULT hr = SetupKeystrokeSink();
    if (FAILED(hr)) {
        return hr;
    }

    hr = SetupThreadMgrEventSink();
    if (FAILED(hr)) {
        CleanupKeystrokeSink();
        return hr;
    }

    return S_OK;
}

void WitnessdTextService::CleanupSinks() {
    CleanupKeystrokeSink();
    CleanupThreadMgrEventSink();

    if (currentContext_ != nullptr) {
        CleanupTextEditSink(currentContext_);
        currentContext_->Release();
        currentContext_ = nullptr;
    }

    if (currentDocMgr_ != nullptr) {
        currentDocMgr_->Release();
        currentDocMgr_ = nullptr;
    }
}

HRESULT WitnessdTextService::SetupKeystrokeSink() {
    if (threadMgr_ == nullptr) {
        return E_FAIL;
    }

    HRESULT hr = threadMgr_->QueryInterface(IID_ITfKeystrokeMgr, (void**)&keystrokeMgr_);
    if (FAILED(hr)) {
        return hr;
    }

    hr = keystrokeMgr_->AdviseKeyEventSink(clientId_,
                                            static_cast<ITfKeyEventSink*>(this),
                                            TRUE);  // Foreground only
    if (FAILED(hr)) {
        keystrokeMgr_->Release();
        keystrokeMgr_ = nullptr;
        return hr;
    }

    return S_OK;
}

void WitnessdTextService::CleanupKeystrokeSink() {
    if (keystrokeMgr_ != nullptr) {
        keystrokeMgr_->UnadviseKeyEventSink(clientId_);
        keystrokeMgr_->Release();
        keystrokeMgr_ = nullptr;
    }
}

HRESULT WitnessdTextService::SetupThreadMgrEventSink() {
    if (threadMgr_ == nullptr) {
        return E_FAIL;
    }

    ITfSource* pSource = nullptr;
    HRESULT hr = threadMgr_->QueryInterface(IID_ITfSource, (void**)&pSource);
    if (FAILED(hr)) {
        return hr;
    }

    hr = pSource->AdviseSink(IID_ITfThreadMgrEventSink,
                              static_cast<ITfThreadMgrEventSink*>(this),
                              &threadMgrEventSinkCookie_);
    pSource->Release();

    return hr;
}

void WitnessdTextService::CleanupThreadMgrEventSink() {
    if (threadMgr_ != nullptr && threadMgrEventSinkCookie_ != TF_INVALID_COOKIE) {
        ITfSource* pSource = nullptr;
        if (SUCCEEDED(threadMgr_->QueryInterface(IID_ITfSource, (void**)&pSource))) {
            pSource->UnadviseSink(threadMgrEventSinkCookie_);
            pSource->Release();
        }
        threadMgrEventSinkCookie_ = TF_INVALID_COOKIE;
    }
}

HRESULT WitnessdTextService::SetupTextEditSink(ITfContext* pContext) {
    if (pContext == nullptr) {
        return E_INVALIDARG;
    }

    ITfSource* pSource = nullptr;
    HRESULT hr = pContext->QueryInterface(IID_ITfSource, (void**)&pSource);
    if (FAILED(hr)) {
        return hr;
    }

    hr = pSource->AdviseSink(IID_ITfTextEditSink,
                              static_cast<ITfTextEditSink*>(this),
                              &textEditSinkCookie_);
    pSource->Release();

    return hr;
}

void WitnessdTextService::CleanupTextEditSink(ITfContext* pContext) {
    if (pContext != nullptr && textEditSinkCookie_ != TF_INVALID_COOKIE) {
        ITfSource* pSource = nullptr;
        if (SUCCEEDED(pContext->QueryInterface(IID_ITfSource, (void**)&pSource))) {
            pSource->UnadviseSink(textEditSinkCookie_);
            pSource->Release();
        }
        textEditSinkCookie_ = TF_INVALID_COOKIE;
    }
}

int WitnessdTextService::VKToChar(WPARAM vk, LPARAM lParam) {
    BYTE keyState[256];
    if (!GetKeyboardState(keyState)) {
        return 0;
    }

    UINT scanCode = (UINT)((lParam >> 16) & 0xFF);
    WCHAR buffer[4];
    int result = ToUnicode((UINT)vk, scanCode, keyState, buffer, 4, 0);

    if (result == 1) {
        return (int)buffer[0];
    }
    return 0;
}

void WitnessdTextService::UpdateFocusInfo() {
    HWND hwnd = GetForegroundWindow();
    if (hwnd == currentFocusWindow_) {
        return;  // No change
    }

    currentFocusWindow_ = hwnd;

    if (hwnd == nullptr) {
        currentAppPath_.clear();
        currentWindowTitle_.clear();
        return;
    }

    // Get window title
    wchar_t title[256] = {0};
    GetWindowTextW(hwnd, title, 256);
    currentWindowTitle_ = title;

    // Get process path
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess != nullptr) {
        wchar_t path[MAX_PATH] = {0};
        DWORD pathLen = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &pathLen)) {
            currentAppPath_ = path;
        }
        CloseHandle(hProcess);
    }
}

void WitnessdTextService::NotifyFocusChange() {
    std::string appPath = WideToUTF8(currentAppPath_);
    std::string docTitle = WideToUTF8(currentWindowTitle_);

    WitnessdOnFocusChange(const_cast<char*>(appPath.c_str()),
                          const_cast<char*>(docTitle.c_str()));
}

std::string WitnessdTextService::WideToUTF8(const std::wstring& wide) {
    if (wide.empty()) {
        return std::string();
    }

    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return std::string();
    }

    std::string utf8(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], len, nullptr, nullptr);
    return utf8;
}

void WitnessdTextService::ProcessKeystroke(const KeystrokeEvent& event) {
    // This method can be used for async processing if needed
    (void)event;
}
