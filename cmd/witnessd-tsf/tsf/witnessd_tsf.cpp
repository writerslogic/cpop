// witnessd_tsf.cpp
// Windows TSF implementation for Witnessd

#include "witnessd_tsf.h"
#include <string>
#include <shlwapi.h>
#include <strsafe.h>

#pragma comment(lib, "shlwapi.lib")

// Global state
HINSTANCE g_hInstance = nullptr;
std::atomic<LONG> g_dllRefCount{0};
WitnessdClassFactory* g_classFactory = nullptr;

//-----------------------------------------------------------------------------
// DLL Entry Point
//-----------------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        WitnessdInit();
        break;
    case DLL_PROCESS_DETACH:
        WitnessdShutdown();
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

    if (!IsEqualCLSID(rclsid, CLSID_WitnessdTSF)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    if (g_classFactory == nullptr) {
        g_classFactory = new WitnessdClassFactory();
    }

    return g_classFactory->QueryInterface(riid, ppvObject);
}

HRESULT WINAPI DllRegisterServer() {
    // Get DLL path
    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(g_hInstance, dllPath, MAX_PATH)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Register CLSID
    HKEY hKey;
    wchar_t clsidStr[64];
    StringFromGUID2(CLSID_WitnessdTSF, clsidStr, 64);

    std::wstring keyPath = L"CLSID\\";
    keyPath += clsidStr;

    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, keyPath.c_str(), 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
        return E_FAIL;
    }
    RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)L"Witnessd TSF", 26);

    std::wstring inprocPath = keyPath + L"\\InProcServer32";
    HKEY hInprocKey;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, inprocPath.c_str(), 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hInprocKey, nullptr) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return E_FAIL;
    }
    RegSetValueExW(hInprocKey, nullptr, 0, REG_SZ, (const BYTE*)dllPath,
                   (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
    RegSetValueExW(hInprocKey, L"ThreadingModel", 0, REG_SZ, (const BYTE*)L"Apartment", 20);
    RegCloseKey(hInprocKey);
    RegCloseKey(hKey);

    // Register with TSF
    ITfInputProcessorProfiles* pProfiles = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_ITfInputProcessorProfiles,
                                  (void**)&pProfiles);
    if (FAILED(hr)) {
        return hr;
    }

    hr = pProfiles->Register(CLSID_WitnessdTSF);
    if (FAILED(hr)) {
        pProfiles->Release();
        return hr;
    }

    hr = pProfiles->AddLanguageProfile(
        CLSID_WitnessdTSF,
        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        GUID_WitnessdProfile,
        L"Witnessd",
        -1,
        dllPath,
        0,
        0
    );

    pProfiles->Release();

    // Register as a TIP
    ITfCategoryMgr* pCategoryMgr = nullptr;
    hr = CoCreateInstance(CLSID_TF_CategoryMgr, nullptr,
                          CLSCTX_INPROC_SERVER, IID_ITfCategoryMgr,
                          (void**)&pCategoryMgr);
    if (SUCCEEDED(hr)) {
        pCategoryMgr->RegisterCategory(CLSID_WitnessdTSF, GUID_TFCAT_TIP_KEYBOARD, CLSID_WitnessdTSF);
        pCategoryMgr->Release();
    }

    return S_OK;
}

HRESULT WINAPI DllUnregisterServer() {
    // Unregister from TSF
    ITfInputProcessorProfiles* pProfiles = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TF_InputProcessorProfiles, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_ITfInputProcessorProfiles,
                                  (void**)&pProfiles);
    if (SUCCEEDED(hr)) {
        pProfiles->Unregister(CLSID_WitnessdTSF);
        pProfiles->Release();
    }

    // Remove CLSID registry key
    wchar_t clsidStr[64];
    StringFromGUID2(CLSID_WitnessdTSF, clsidStr, 64);
    std::wstring keyPath = L"CLSID\\";
    keyPath += clsidStr;
    SHDeleteKeyW(HKEY_CLASSES_ROOT, keyPath.c_str());

    return S_OK;
}

//-----------------------------------------------------------------------------
// WitnessdClassFactory
//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------
// WitnessdTextService
//-----------------------------------------------------------------------------

WitnessdTextService::WitnessdTextService()
    : refCount_(1),
      threadMgr_(nullptr),
      clientId_(0),
      keystrokeMgr_(nullptr),
      keystrokeSinkCookie_(0),
      isActivated_(false) {
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

    WitnessdTextService* pService = new WitnessdTextService();
    if (pService == nullptr) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pService->QueryInterface(riid, ppvObject);
    pService->Release();
    return hr;
}

STDMETHODIMP WitnessdTextService::QueryInterface(REFIID riid, void** ppvObject) {
    if (ppvObject == nullptr) {
        return E_INVALIDARG;
    }

    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ITfTextInputProcessor) ||
        IsEqualIID(riid, IID_ITfTextInputProcessorEx)) {
        *ppvObject = static_cast<ITfTextInputProcessorEx*>(this);
    } else if (IsEqualIID(riid, IID_ITfKeyEventSink)) {
        *ppvObject = static_cast<ITfKeyEventSink*>(this);
    } else if (IsEqualIID(riid, IID_ITfDisplayAttributeProvider)) {
        *ppvObject = static_cast<ITfDisplayAttributeProvider*>(this);
    } else {
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

STDMETHODIMP WitnessdTextService::Activate(ITfThreadMgr* pThreadMgr, TfClientId tfClientId) {
    return ActivateEx(pThreadMgr, tfClientId, 0);
}

STDMETHODIMP WitnessdTextService::ActivateEx(ITfThreadMgr* pThreadMgr, TfClientId tfClientId, DWORD dwFlags) {
    if (isActivated_) {
        return S_OK;
    }

    threadMgr_ = pThreadMgr;
    threadMgr_->AddRef();
    clientId_ = tfClientId;

    HRESULT hr = SetupKeySinks();
    if (FAILED(hr)) {
        Deactivate();
        return hr;
    }

    // Start a session
    WitnessdStartSession((char*)"windows.tsf", (char*)"default");

    isActivated_ = true;
    return S_OK;
}

STDMETHODIMP WitnessdTextService::Deactivate() {
    if (!isActivated_) {
        return S_OK;
    }

    // End session
    char* evidence = WitnessdEndSession();
    if (evidence != nullptr) {
        WitnessdFreeString(evidence);
    }

    CleanupKeySinks();

    if (threadMgr_ != nullptr) {
        threadMgr_->Release();
        threadMgr_ = nullptr;
    }

    clientId_ = 0;
    isActivated_ = false;
    return S_OK;
}

HRESULT WitnessdTextService::SetupKeySinks() {
    HRESULT hr = threadMgr_->QueryInterface(IID_ITfKeystrokeMgr, (void**)&keystrokeMgr_);
    if (FAILED(hr)) {
        return hr;
    }

    hr = keystrokeMgr_->AdviseKeyEventSink(clientId_, static_cast<ITfKeyEventSink*>(this), TRUE);
    if (FAILED(hr)) {
        keystrokeMgr_->Release();
        keystrokeMgr_ = nullptr;
        return hr;
    }

    return S_OK;
}

void WitnessdTextService::CleanupKeySinks() {
    if (keystrokeMgr_ != nullptr) {
        keystrokeMgr_->UnadviseKeyEventSink(clientId_);
        keystrokeMgr_->Release();
        keystrokeMgr_ = nullptr;
    }
}

STDMETHODIMP WitnessdTextService::OnSetFocus(BOOL fForeground) {
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnTestKeyDown(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) {
    *pfEaten = FALSE; // Don't eat keys - pass through
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnTestKeyUp(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) {
    *pfEaten = FALSE;
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnKeyDown(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) {
    *pfEaten = FALSE; // Pass through mode

    // Get character from virtual key
    int charCode = VKToChar(wParam, lParam);

    // Process through witnessd engine
    WitnessdOnKeyDown((uint16_t)wParam, (int32_t)charCode);

    // Record text commit for printable characters
    if (charCode >= 0x20 && charCode <= 0x7E) {
        char buf[2] = { (char)charCode, 0 };
        WitnessdOnTextCommit(buf);
    }

    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnKeyUp(ITfContext* pContext, WPARAM wParam, LPARAM lParam, BOOL* pfEaten) {
    *pfEaten = FALSE;
    return S_OK;
}

STDMETHODIMP WitnessdTextService::OnPreservedKey(ITfContext* pContext, REFGUID rguid, BOOL* pfEaten) {
    *pfEaten = FALSE;
    return S_OK;
}

int WitnessdTextService::VKToChar(WPARAM vk, LPARAM lParam) {
    // Get keyboard state
    BYTE keyState[256];
    if (!GetKeyboardState(keyState)) {
        return 0;
    }

    // Convert scan code to character
    UINT scanCode = (lParam >> 16) & 0xFF;
    WCHAR buffer[4];
    int result = ToUnicode((UINT)vk, scanCode, keyState, buffer, 4, 0);

    if (result == 1) {
        return (int)buffer[0];
    }
    return 0;
}

STDMETHODIMP WitnessdTextService::EnumDisplayAttributeInfo(IEnumTfDisplayAttributeInfo** ppEnum) {
    if (ppEnum == nullptr) {
        return E_INVALIDARG;
    }
    *ppEnum = nullptr;
    return E_NOTIMPL;
}

STDMETHODIMP WitnessdTextService::GetDisplayAttributeInfo(REFGUID guid, ITfDisplayAttributeInfo** ppInfo) {
    if (ppInfo == nullptr) {
        return E_INVALIDARG;
    }
    *ppInfo = nullptr;
    return E_NOTIMPL;
}
