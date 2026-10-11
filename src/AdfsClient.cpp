#include "AdfsClient.h"
#include "Util.h"
#include "Log.h"
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#if defined(__MINGW32__)
#include <msxml2.h>   // msxml6.h von MinGW ist fehlerhaft; die DOM-Schnittstellen sind identisch
#else
#include <msxml6.h>
#endif
#include <memory>
#include <cwctype>

namespace {

// CLSID_DOMDocument60 – lokal definiert, damit keine zusätzliche Import-Bibliothek nötig ist.
const CLSID kClsidDomDocument60 = { 0x88d96a05, 0xf192, 0x11d4, { 0xa6, 0x5f, 0x00, 0x40, 0x96, 0x32, 0x51, 0xe5 } };

const wchar_t* kNamespaces =
    L"xmlns:s12='http://www.w3.org/2003/05/soap-envelope' "
    L"xmlns:s11='http://schemas.xmlsoap.org/soap/envelope/' "
    L"xmlns:t='http://docs.oasis-open.org/ws-sx/ws-trust/200512' "
    L"xmlns:t05='http://schemas.xmlsoap.org/ws/2005/02/trust' "
    L"xmlns:saml2='urn:oasis:names:tc:SAML:2.0:assertion' "
    L"xmlns:saml1='urn:oasis:names:tc:SAML:1.0:assertion' "
    L"xmlns:xenc='http://www.w3.org/2001/04/xmlenc#'";

struct WinHttpHandle {
    HINTERNET h = nullptr;
    WinHttpHandle() = default;
    explicit WinHttpHandle(HINTERNET x) : h(x) {}
    ~WinHttpHandle() { if (h) WinHttpCloseHandle(h); }
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;
    operator HINTERNET() const { return h; }
};

struct Bstr {
    BSTR b = nullptr;
    Bstr() = default;
    explicit Bstr(const wchar_t* s) : b(SysAllocString(s)) {}
    explicit Bstr(const std::wstring& s) : b(SysAllocStringLen(s.data(), (UINT)s.size())) {}
    ~Bstr() { if (b) SysFreeString(b); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    BSTR* operator&() { return &b; }
    operator BSTR() const { return b; }
    std::wstring str() const { return b ? std::wstring(b, SysStringLen(b)) : std::wstring(); }
};

template <class T> struct ComPtr {
    T* p = nullptr;
    ~ComPtr() { if (p) p->Release(); }
    T** operator&() { if (p) { p->Release(); p = nullptr; } return &p; }
    T* operator->() const { return p; }
    explicit operator bool() const { return p != nullptr; }
};

std::wstring NodeText(IXMLDOMNode* node) {
    Bstr t;
    if (node && SUCCEEDED(node->get_text(&t))) return t.str();
    return {};
}

std::wstring SelectText(IXMLDOMNode* ctx, const wchar_t* xpath) {
    ComPtr<IXMLDOMNode> n;
    Bstr q(xpath);
    if (ctx && ctx->selectSingleNode(q, &n) == S_OK && n) return util::Trim(NodeText(n.p));
    return {};
}

bool IsTransportError(DWORD err) {
    switch (err) {
    case ERROR_WINHTTP_CANNOT_CONNECT:
    case ERROR_WINHTTP_CONNECTION_ERROR:
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
    case ERROR_WINHTTP_TIMEOUT:
    case ERROR_WINHTTP_SECURE_FAILURE:
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE:
    case ERROR_WINHTTP_OPERATION_CANCELLED:
    case ERROR_WINHTTP_RESEND_REQUEST:
        return true;
    default:
        return false;
    }
}

std::wstring NormalizeThumbprint(const std::wstring& s) {
    std::wstring r;
    for (wchar_t c : s)
        if (iswxdigit(c)) r += (wchar_t)towupper(c);
    return r;
}

} // namespace

// ---------------------------------------------------------------------------

std::vector<std::wstring> AdfsResult::Values(const std::wstring& claimType) const {
    std::vector<std::wstring> v;
    for (const auto& c : claims)
        if (util::EqualsI(c.first, claimType)) v.push_back(c.second);
    return v;
}

std::wstring AdfsResult::First(const std::wstring& claimType) const {
    for (const auto& c : claims)
        if (util::EqualsI(c.first, claimType)) return c.second;
    return {};
}

bool AdfsResult::Has(const std::wstring& claimType, const std::vector<std::wstring>& anyOf) const {
    for (const auto& v : Values(claimType))
        for (const auto& want : anyOf)
            if (util::EqualsI(v, want)) return true;
    return false;
}

const wchar_t* StatusName(AdfsResult::Status s) {
    switch (s) {
    case AdfsResult::Ok:                 return L"Ok";
    case AdfsResult::InvalidCredentials: return L"InvalidCredentials";
    case AdfsResult::AccessDenied:       return L"AccessDenied";
    case AdfsResult::NetworkError:       return L"NetworkError";
    case AdfsResult::ServerError:        return L"ServerError";
    case AdfsResult::TokenError:         return L"TokenError";
    case AdfsResult::ConfigError:        return L"ConfigError";
    }
    return L"?";
}

// ---------------------------------------------------------------------------

std::string AdfsClient::BuildRequest(const std::wstring& endpoint, const std::wstring& username,
                                     const std::wstring& password) const {
    std::wstring x;
    x.reserve(4096);
    x += L"<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
         L" xmlns:a=\"http://www.w3.org/2005/08/addressing\""
         L" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
         L"<s:Header>"
         L"<a:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>"
         L"<a:MessageID>urn:uuid:";
    x += util::NewUuid();
    x += L"</a:MessageID>"
         L"<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
         L"<a:To s:mustUnderstand=\"1\">";
    x += util::XmlEscape(endpoint);
    x += L"</a:To>"
         L"<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
         L"<u:Timestamp u:Id=\"_0\"><u:Created>";
    x += util::IsoUtcNow(0);
    x += L"</u:Created><u:Expires>";
    x += util::IsoUtcNow(300);
    x += L"</u:Expires></u:Timestamp>"
         L"<o:UsernameToken u:Id=\"uuid-";
    x += util::NewUuid();
    x += L"\"><o:Username>";
    x += util::XmlEscape(username);
    x += L"</o:Username><o:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">";
    std::wstring escapedPassword = util::XmlEscape(password);
    x += escapedPassword;
    util::Wipe(escapedPassword);
    x += L"</o:Password></o:UsernameToken>"
         L"</o:Security>"
         L"</s:Header>"
         L"<s:Body>"
         L"<trust:RequestSecurityToken xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
         L"<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">"
         L"<a:EndpointReference><a:Address>";
    x += util::XmlEscape(cfg_.relyingParty);
    x += L"</a:Address></a:EndpointReference></wsp:AppliesTo>"
         L"<trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>"
         L"<trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>"
         L"<trust:TokenType>";
    x += util::XmlEscape(cfg_.tokenType);
    x += L"</trust:TokenType>"
         L"</trust:RequestSecurityToken>"
         L"</s:Body>"
         L"</s:Envelope>";

    std::string body = util::ToUtf8(x);
    util::Wipe(x);
    return body;
}

AdfsResult AdfsClient::Authenticate(const std::wstring& username, const std::wstring& password) const {
    AdfsResult r;
    if (!cfg_.IsConfigured()) {
        r.status = AdfsResult::ConfigError;
        r.message = L"AdfsUrl oder RelyingParty ist nicht konfiguriert";
        return r;
    }

    std::wstring endpoint = cfg_.Endpoint();
    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[2048] = {};
    uc.lpszHostName = host;    uc.dwHostNameLength = _countof(host);
    uc.lpszUrlPath = path;     uc.dwUrlPathLength = _countof(path);
    if (!WinHttpCrackUrl(endpoint.c_str(), 0, 0, &uc) || uc.nScheme != INTERNET_SCHEME_HTTPS) {
        r.status = AdfsResult::ConfigError;
        r.message = L"Ungültiger oder nicht-HTTPS Endpunkt: " + endpoint;
        return r;
    }

    LOGI(L"ADFS-Anfrage für '%ls' an %ls", username.c_str(), endpoint.c_str());

    WinHttpHandle session(cfg_.proxy.empty()
        ? WinHttpOpen(L"ADFSCreds/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)
        : WinHttpOpen(L"ADFSCreds/1.0", WINHTTP_ACCESS_TYPE_NAMED_PROXY, cfg_.proxy.c_str(), L"<local>", 0));
    if (!session) {
        r.status = AdfsResult::NetworkError;
        r.message = L"WinHttpOpen: " + util::ErrorText(GetLastError());
        return r;
    }

    int ms = (int)cfg_.timeoutSeconds * 1000;
    WinHttpSetTimeouts(session, ms, ms, ms, ms);

    WinHttpHandle connect(WinHttpConnect(session, host, uc.nPort, 0));
    WinHttpHandle request(connect ? WinHttpOpenRequest(connect, L"POST", path, nullptr, WINHTTP_NO_REFERER,
                                                       WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)
                                  : nullptr);
    if (!request) {
        r.status = AdfsResult::NetworkError;
        r.message = L"WinHttpOpenRequest: " + util::ErrorText(GetLastError());
        return r;
    }

    // Keine Weiterleitungen folgen – die Zugangsdaten sollen nur an den konfigurierten Server gehen.
    DWORD disable = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES;
    WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable));

    std::string body = BuildRequest(endpoint, username, password);
    const wchar_t* headers = L"Content-Type: application/soap+xml; charset=utf-8\r\n";

    // Erst nur die Header senden (TLS-Handshake ist danach abgeschlossen), dann das
    // Zertifikat prüfen und erst danach den Body mit dem Passwort übertragen.
    if (!WinHttpSendRequest(request, headers, (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, (DWORD)body.size(), 0)) {
        DWORD err = GetLastError();
        util::Wipe(body);
        r.status = AdfsResult::NetworkError;
        r.message = L"WinHttpSendRequest: " + util::ErrorText(err);
        return r;
    }

    if (!cfg_.pinnedThumbprints.empty()) {
        PCCERT_CONTEXT cert = nullptr;
        DWORD cb = sizeof(cert);
        bool ok = false;
        std::wstring seen;
        if (WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &cb) && cert) {
            BYTE hash[20];
            DWORD hcb = sizeof(hash);
            if (CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash, &hcb)) {
                wchar_t hex[3];
                for (DWORD i = 0; i < hcb; ++i) { swprintf(hex, 3, L"%02X", hash[i]); seen += hex; }
                for (const auto& pin : cfg_.pinnedThumbprints)
                    if (NormalizeThumbprint(pin) == seen) ok = true;
            }
            CertFreeCertificateContext(cert);
        }
        if (!ok) {
            util::Wipe(body);
            r.status = AdfsResult::NetworkError;
            r.message = L"TLS-Zertifikat des ADFS-Servers entspricht keinem gepinnten Fingerabdruck (gesehen: " + seen + L")";
            LOGE(L"%ls", r.message.c_str());
            return r;
        }
    }

    DWORD written = 0;
    BOOL sent = WinHttpWriteData(request, body.data(), (DWORD)body.size(), &written);
    util::Wipe(body);
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        DWORD err = GetLastError();
        r.status = AdfsResult::NetworkError;
        r.message = L"Senden/Empfangen fehlgeschlagen: " + util::ErrorText(err);
        if (!IsTransportError(err)) LOGW(L"Unerwarteter WinHTTP-Fehler %lu", err);
        return r;
    }

    DWORD statusCode = 0, scb = sizeof(statusCode);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                        &statusCode, &scb, WINHTTP_NO_HEADER_INDEX);

    std::string response;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(request, &avail) || avail == 0) break;
        if (response.size() + avail > 4 * 1024 * 1024) break;  // Schutz vor Riesenantworten
        size_t old = response.size();
        response.resize(old + avail);
        DWORD read = 0;
        if (!WinHttpReadData(request, &response[old], avail, &read)) { response.resize(old); break; }
        response.resize(old + read);
    }

    LOGD(L"HTTP-Status %lu, %u Bytes", statusCode, (unsigned)response.size());
    return ParseResponse(statusCode, response);
}

AdfsResult AdfsClient::ParseResponse(DWORD httpStatus, const std::string& body) const {
    AdfsResult r;

    ComPtr<IXMLDOMDocument2> doc;
    HRESULT hr = CoCreateInstance(kClsidDomDocument60, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IXMLDOMDocument2),
                                  reinterpret_cast<void**>(&doc));
    if (FAILED(hr)) {
        r.status = AdfsResult::ServerError;
        r.message = L"MSXML6 nicht verfügbar";
        return r;
    }
    doc->put_async(VARIANT_FALSE);
    doc->put_validateOnParse(VARIANT_FALSE);
    doc->put_resolveExternals(VARIANT_FALSE);
    {
        VARIANT v; VariantInit(&v);
        v.vt = VT_BOOL; v.boolVal = VARIANT_TRUE;
        Bstr p(L"ProhibitDTD");
        doc->setProperty(p, v);
        v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"XPath");
        Bstr sl(L"SelectionLanguage");
        doc->setProperty(sl, v);
        VariantClear(&v);
        v.vt = VT_BSTR; v.bstrVal = SysAllocString(kNamespaces);
        Bstr sn(L"SelectionNamespaces");
        doc->setProperty(sn, v);
        VariantClear(&v);
    }

    std::wstring text = util::FromUtf8(body);
    Bstr xml(text);
    VARIANT_BOOL loaded = VARIANT_FALSE;
    if (body.empty() || FAILED(doc->loadXML(xml, &loaded)) || loaded != VARIANT_TRUE) {
        r.status = (httpStatus >= 500 || httpStatus == 0) ? AdfsResult::NetworkError : AdfsResult::ServerError;
        wchar_t buf[96];
        swprintf(buf, 96, L"Keine gültige SOAP-Antwort (HTTP %lu)", httpStatus);
        r.message = buf;
        return r;
    }

    IXMLDOMNode* root = nullptr;
    doc->QueryInterface(__uuidof(IXMLDOMNode), reinterpret_cast<void**>(&root));
    std::unique_ptr<IXMLDOMNode, void (*)(IXMLDOMNode*)> rootGuard(root, [](IXMLDOMNode* n) { if (n) n->Release(); });

    // --- SOAP-Fault ---
    std::wstring faultReason = SelectText(root, L"//s12:Fault/s12:Reason/s12:Text");
    if (faultReason.empty()) faultReason = SelectText(root, L"//s11:Fault/faultstring");
    std::wstring faultCode = SelectText(root, L"//s12:Fault/s12:Code/s12:Subcode/s12:Value");
    if (faultCode.empty()) faultCode = SelectText(root, L"//s11:Fault/faultcode");
    if (!faultReason.empty() || !faultCode.empty()) {
        r.message = L"SOAP-Fault: " + faultCode + L" – " + faultReason;
        std::wstring lc = util::ToLower(faultCode + L" " + faultReason);
        if (lc.find(L"failedauthentication") != std::wstring::npos || lc.find(L"id3242") != std::wstring::npos ||
            lc.find(L"could not be authenticated") != std::wstring::npos) {
            r.status = AdfsResult::InvalidCredentials;
        } else if (lc.find(L"authoriz") != std::wstring::npos || lc.find(L"accessdenied") != std::wstring::npos) {
            r.status = AdfsResult::AccessDenied;
        } else {
            r.status = AdfsResult::ServerError;
        }
        return r;
    }

    if (httpStatus != 200) {
        r.status = httpStatus >= 500 ? AdfsResult::NetworkError : AdfsResult::ServerError;
        wchar_t buf[64];
        swprintf(buf, 64, L"Unerwarteter HTTP-Status %lu", httpStatus);
        r.message = buf;
        return r;
    }

    // --- Token suchen ---
    ComPtr<IXMLDOMNode> rst;
    {
        Bstr q(L"//t:RequestedSecurityToken | //t05:RequestedSecurityToken");
        root->selectSingleNode(q, &rst);
    }
    if (!rst) {
        r.status = AdfsResult::ServerError;
        r.message = L"Antwort enthält kein RequestedSecurityToken";
        return r;
    }

    ComPtr<IXMLDOMNode> enc;
    {
        Bstr q(L".//xenc:EncryptedData | .//saml2:EncryptedAssertion");
        rst->selectSingleNode(q, &enc);
    }
    if (enc) {
        r.status = AdfsResult::TokenError;
        r.message = L"Das Token ist verschlüsselt. Bitte in der ADFS-Vertrauensstellung kein Verschlüsselungszertifikat hinterlegen.";
        return r;
    }

    ComPtr<IXMLDOMNode> assertion;
    bool saml2 = true;
    {
        Bstr q(L"saml2:Assertion");
        rst->selectSingleNode(q, &assertion);
    }
    if (!assertion) {
        saml2 = false;
        Bstr q(L"saml1:Assertion");
        rst->selectSingleNode(q, &assertion);
    }
    if (!assertion) {
        r.status = AdfsResult::TokenError;
        r.message = L"Keine SAML-Assertion im Token gefunden";
        return r;
    }

    // --- Gültigkeit prüfen (5 Minuten Toleranz) ---
    std::wstring notBefore = SelectText(assertion.p, saml2 ? L"saml2:Conditions/@NotBefore" : L"saml1:Conditions/@NotBefore");
    std::wstring notAfter  = SelectText(assertion.p, saml2 ? L"saml2:Conditions/@NotOnOrAfter" : L"saml1:Conditions/@NotOnOrAfter");
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER n; n.LowPart = now.dwLowDateTime; n.HighPart = now.dwHighDateTime;
    const ULONGLONG skew = 5ULL * 60 * 10000000ULL;
    FILETIME ft;
    if (!notBefore.empty() && util::ParseIsoUtc(notBefore, &ft)) {
        ULARGE_INTEGER v; v.LowPart = ft.dwLowDateTime; v.HighPart = ft.dwHighDateTime;
        if (n.QuadPart + skew < v.QuadPart) {
            r.status = AdfsResult::TokenError;
            r.message = L"Token noch nicht gültig (NotBefore " + notBefore + L") – Uhrzeit des Clients prüfen";
            return r;
        }
    }
    if (!notAfter.empty() && util::ParseIsoUtc(notAfter, &ft)) {
        ULARGE_INTEGER v; v.LowPart = ft.dwLowDateTime; v.HighPart = ft.dwHighDateTime;
        if (n.QuadPart > v.QuadPart + skew) {
            r.status = AdfsResult::TokenError;
            r.message = L"Token abgelaufen (NotOnOrAfter " + notAfter + L") – Uhrzeit des Clients prüfen";
            return r;
        }
    }

    std::wstring audience = SelectText(assertion.p, saml2 ? L"saml2:Conditions/saml2:AudienceRestriction/saml2:Audience"
                                                          : L"saml1:Conditions/saml1:AudienceRestrictionCondition/saml1:Audience");
    if (!audience.empty() && !util::EqualsI(audience, cfg_.relyingParty)) {
        r.status = AdfsResult::TokenError;
        r.message = L"Audience '" + audience + L"' passt nicht zur RelyingParty '" + cfg_.relyingParty + L"'";
        return r;
    }

    r.nameId = SelectText(assertion.p, saml2 ? L"saml2:Subject/saml2:NameID"
                                             : L"saml1:AttributeStatement/saml1:Subject/saml1:NameIdentifier");

    // --- Claims einsammeln ---
    ComPtr<IXMLDOMNodeList> attrs;
    {
        Bstr q(saml2 ? L".//saml2:AttributeStatement/saml2:Attribute" : L".//saml1:AttributeStatement/saml1:Attribute");
        assertion->selectNodes(q, &attrs);
    }
    long count = 0;
    if (attrs) attrs->get_length(&count);
    for (long i = 0; i < count; ++i) {
        ComPtr<IXMLDOMNode> attr;
        if (attrs->get_item(i, &attr) != S_OK || !attr) continue;
        std::wstring type;
        if (saml2) {
            type = SelectText(attr.p, L"@Name");
        } else {
            std::wstring ns = SelectText(attr.p, L"@AttributeNamespace");
            std::wstring nm = SelectText(attr.p, L"@AttributeName");
            type = ns.empty() ? nm : ns + L"/" + nm;
        }
        ComPtr<IXMLDOMNodeList> values;
        Bstr q(saml2 ? L"saml2:AttributeValue" : L"saml1:AttributeValue");
        attr->selectNodes(q, &values);
        long vc = 0;
        if (values) values->get_length(&vc);
        for (long j = 0; j < vc; ++j) {
            ComPtr<IXMLDOMNode> val;
            if (values->get_item(j, &val) == S_OK && val) r.claims.emplace_back(type, util::Trim(NodeText(val.p)));
        }
    }

    r.status = AdfsResult::Ok;
    r.message = L"Token erhalten (" + std::to_wstring(r.claims.size()) + L" Claims)";
    return r;
}
