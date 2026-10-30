#include "stdafx.h"
#include "Lua.h"
#include "Hooks.h"
#include "strings.h"
#include "Output.h"
#include <commdlg.h>
#include <algorithm>
#include <cstdarg>
#include <condition_variable>
#include <deque>
#include <utility>
#include <mutex>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")
#endif

namespace
{
constexpr UINT ui_event = WM_APP + 1;
constexpr int execute_id = 1001;
constexpr int load_id = 1002;
constexpr int clear_id = 1003;
constexpr size_t script_limit = 16 * 1024 * 1024;
HWND main_window = nullptr;
HWND output_box = nullptr;
HWND editor_box = nullptr;
HWND execute_button = nullptr;
HWND load_button = nullptr;
HWND clear_button = nullptr;
HFONT code_font = nullptr;
std::mutex window_mutex;
std::mutex error_mutex;
std::deque<std::pair<HWND, std::wstring>> pending_errors;
bool error_visible = false;
std::mutex job_mutex;
std::condition_variable job_changed;
std::string pending_source;
bool job_pending = false;
bool stopping = false;
bool ready = false;
bool busy = false;
HANDLE state_captured = nullptr;
HANDLE stop_event = nullptr;
HANDLE window_created = nullptr;
C_Hook hook_gettop;
int lua_state = 0;

enum class event_kind : WPARAM { output, ready, finished, error };

std::wstring from_bytes(const std::string& bytes)
{
    if (bytes.empty()) return {};
    UINT encoding = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int size = MultiByteToWideChar(encoding, flags, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (!size)
    {
        encoding = CP_ACP;
        flags = 0;
        size = MultiByteToWideChar(encoding, flags, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    }
    if (!size) return {};
    std::wstring text(size, L'\0');
    MultiByteToWideChar(encoding, flags, bytes.data(), static_cast<int>(bytes.size()), &text[0], size);
    return text;
}

bool to_bytes(const std::wstring& text, std::string& bytes)
{
    bytes.clear();
    if (text.empty()) return true;
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!size) return false;
    bytes.resize(size);
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), &bytes[0], size, nullptr, nullptr) != 0;
}

void show_error(HWND owner, const std::wstring& message)
{
    std::unique_lock<std::mutex> lock(error_mutex);
    pending_errors.emplace_back(owner, message);
    if (error_visible) return;
    error_visible = true;
    while (!pending_errors.empty())
    {
        auto next = std::move(pending_errors.front());
        pending_errors.pop_front();
        lock.unlock();
        MessageBoxW(IsWindow(next.first) ? next.first : nullptr, next.second.c_str(), L"", 0x0);
        lock.lock();
    }
    error_visible = false;
}

void post_event(event_kind kind, const std::string& text = {})
{
    std::wstring* message = text.empty() ? nullptr : new std::wstring(from_bytes(text));
    std::lock_guard<std::mutex> lock(window_mutex);
    if (!main_window || !PostMessageW(main_window, ui_event, static_cast<WPARAM>(kind), reinterpret_cast<LPARAM>(message)))
        delete message;
}

std::wstring windows_lines(const std::wstring& text)
{
    std::wstring normalized;
    normalized.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i)
    {
        if (text[i] == L'\r')
        {
            if (i + 1 < text.size() && text[i + 1] == L'\n') ++i;
            normalized += L"\r\n";
        }
        else if (text[i] == L'\n') normalized += L"\r\n";
        else normalized += text[i];
    }
    return normalized;
}

void append_output(const std::wstring& text)
{
    std::wstring normalized = windows_lines(text);
    while (!normalized.empty() && (normalized.back() == L'\r' || normalized.back() == L'\n')) normalized.pop_back();
    if (normalized.empty()) return;
    int length = GetWindowTextLengthW(output_box);
    if (length) normalized.insert(0, L"\r\n");
    if (length + normalized.size() > 1024 * 1024)
    {
        SendMessageW(output_box, EM_SETSEL, 0, length / 2);
        SendMessageW(output_box, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L""));
    }
    SendMessageW(output_box, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(output_box, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(normalized.c_str()));
    SendMessageW(output_box, EM_SCROLLCARET, 0, 0);
}

int lua_gettop_hook(int state)
{
    hook_gettop.removeHook();
    lua_state = lua::newthread(state);
    std::string retain = enc("local parent = getfenv(0); local environment = {}; setmetatable(environment, {__index = parent}); setfenv(0, environment); _G[coroutine.running()] = true");
    int status = lua::loadbuffer(lua_state, &retain[0], retain.size(), &retain[0]);
    if (status == 0) status = lua::pcall(lua_state, 0, 0, 0);
    if (status != 0)
    {
        const char* error = lua::tolstring(lua_state, -1, nullptr);
        if (error) ui::write(error);
        lua_state = 0;
    }
    lua::settop(state, -2);
    if (lua_state && !lua::bind_native_globals(lua_state))
    {
        ui::error(enc("Can't bind native globals."));
        lua_state = 0;
    }
    if (lua_state) ui::writef(enc("captured state : %d").c_str(), lua_state);
    int top = lua::gettop(state);
    SetEvent(state_captured);
    return top;
}

DWORD WINAPI execution_worker(LPVOID)
{
    if (!lua::initialize()) return 0;
    ui::write(enc("Hooking lua_gettop and capturing lua state..."));
    hook_gettop.setSubs(reinterpret_cast<void*>(lua::gettop), reinterpret_cast<void*>(lua_gettop_hook));
    if (!hook_gettop.installHook())
    {
        ui::error(enc("Can't capture Lua state."));
        return 0;
    }
    HANDLE events[] = { stop_event, state_captured };
    if (WaitForMultipleObjects(2, events, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) return 0;
    if (!lua_state) return 0;
    post_event(event_kind::ready);
    while (true)
    {
        std::string source;
        {
            std::unique_lock<std::mutex> lock(job_mutex);
            job_changed.wait(lock, [] { return stopping || job_pending; });
            if (stopping) return 0;
            source.swap(pending_source);
            job_pending = false;
        }
        int script_state = lua::newthread(lua_state);
        int status = lua::loadbuffer(script_state, &source[0], source.size(), &source[0]);
        if (status == 0)
        {
            status = lua::resume(script_state, 0);
            if (status == 1) status = 0;
        }
        if (status != 0)
        {
            const char* error = lua::tolstring(script_state, -1, nullptr);
            if (error) ui::write(error);
        }
        post_event(event_kind::finished);
    }
}

void layout(HWND window)
{
    RECT area = {};
    GetClientRect(window, &area);
    int width = (std::max)(1, static_cast<int>(area.right) - 24);
    int output_height = (std::max)(150, static_cast<int>(area.bottom) / 2 - 28);
    int editor_y = output_height + 22;
    int button_y = (std::max)(editor_y + 80, static_cast<int>(area.bottom) - 40);
    MoveWindow(output_box, 12, 12, width, output_height, TRUE);
    MoveWindow(editor_box, 12, editor_y, width, (std::max)(1, button_y - editor_y - 10), TRUE);
    MoveWindow(execute_button, 12, button_y, 90, 26, TRUE);
    MoveWindow(load_button, 110, button_y, 90, 26, TRUE);
    MoveWindow(clear_button, 208, button_y, 90, 26, TRUE);
}

void load_script(HWND window)
{
    wchar_t path[32768] = {};
    OPENFILENAMEW dialog = {};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = window;
    dialog.lpstrFile = path;
    dialog.nMaxFile = static_cast<DWORD>(sizeof(path) / sizeof(path[0]));
    dialog.lpstrFilter = L"Lua scripts (*.lua;*.txt)\0*.lua;*.txt\0All files (*.*)\0*.*\0\0";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&dialog))
    {
        if (CommDlgExtendedError()) ui::error(enc("Failed to load"));
        return;
    }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        ui::error(enc("Failed to load"));
        return;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0)
    {
        CloseHandle(file);
        ui::error(enc("Failed to load"));
        return;
    }
    if (size.QuadPart > static_cast<LONGLONG>(script_limit))
    {
        CloseHandle(file);
        ui::error(enc("Failed to load"));
        return;
    }
    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    bool loaded = bytes.empty() || (ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()), &read, nullptr) && read == bytes.size());
    CloseHandle(file);
    if (!loaded)
    {
        ui::error(enc("Failed to load"));
        return;
    }
    std::wstring text;
    if (bytes.size() >= 2 && ((static_cast<unsigned char>(bytes[0]) == 0xff && static_cast<unsigned char>(bytes[1]) == 0xfe) ||
                             (static_cast<unsigned char>(bytes[0]) == 0xfe && static_cast<unsigned char>(bytes[1]) == 0xff)))
    {
        if (bytes.size() % 2)
        {
            ui::error(enc("Failed to load"));
            return;
        }
        bool little = static_cast<unsigned char>(bytes[0]) == 0xff;
        for (size_t i = 2; i + 1 < bytes.size(); i += 2)
        {
            unsigned first = static_cast<unsigned char>(bytes[i]);
            unsigned second = static_cast<unsigned char>(bytes[i + 1]);
            text += static_cast<wchar_t>(little ? first | (second << 8) : (first << 8) | second);
        }
    }
    else
    {
        if (bytes.size() >= 3 && bytes.compare(0, 3, "\xef\xbb\xbf") == 0) bytes.erase(0, 3);
        text = from_bytes(bytes);
    }
    if (text.find(L'\0') != std::wstring::npos)
    {
        ui::error(enc("Failed to load"));
        return;
    }
    text = windows_lines(text);
    if (!SetWindowTextW(editor_box, text.c_str()))
    {
        ui::error(enc("Failed to load"));
        return;
    }
    SetFocus(editor_box);
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        HINSTANCE instance = reinterpret_cast<LPCREATESTRUCTW>(lparam)->hInstance;
        output_box = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL, 0, 0, 0, 0, window, nullptr, instance, nullptr);
        editor_box = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_WANTRETURN | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_NOHIDESEL, 0, 0, 0, 0, window, nullptr, instance, nullptr);
        execute_button = CreateWindowW(L"BUTTON", L"Execute", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, window, reinterpret_cast<HMENU>(execute_id), instance, nullptr);
        load_button = CreateWindowW(L"BUTTON", L"Load", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, window, reinterpret_cast<HMENU>(load_id), instance, nullptr);
        clear_button = CreateWindowW(L"BUTTON", L"Clear", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 0, 0, window, reinterpret_cast<HMENU>(clear_id), instance, nullptr);
        if (!output_box || !editor_box || !execute_button || !load_button || !clear_button) return -1;
        HDC dc = GetDC(window);
        int height = -MulDiv(10, GetDeviceCaps(dc, LOGPIXELSY), 72);
        ReleaseDC(window, dc);
        code_font = CreateFontW(height, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"System");
        HFONT font = code_font ? code_font : reinterpret_cast<HFONT>(GetStockObject(SYSTEM_FONT));
        SendMessageW(output_box, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        SendMessageW(editor_box, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        for (HWND control : { execute_button, load_button, clear_button })
            SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        SendMessageW(editor_box, EM_LIMITTEXT, script_limit, 0);
        SendMessageW(output_box, EM_LIMITTEXT, 1024 * 1024, 0);
        EnableWindow(execute_button, FALSE);
        layout(window);
        return 0;
    }
    case WM_SIZE:
        layout(window);
        return 0;
    case WM_GETMINMAXINFO:
    {
        auto* limits = reinterpret_cast<MINMAXINFO*>(lparam);
        limits->ptMinTrackSize.x = 370;
        limits->ptMinTrackSize.y = 400;
        return 0;
    }
    case WM_COMMAND:
        if (HIWORD(wparam) != BN_CLICKED) break;
        switch (LOWORD(wparam))
        {
        case execute_id:
            if (ready && !busy)
            {
                int length = GetWindowTextLengthW(editor_box);
                if (!length) return 0;
                std::wstring text(static_cast<size_t>(length) + 1, L'\0');
                int copied = GetWindowTextW(editor_box, &text[0], length + 1);
                text.resize(copied);
                std::string source;
                if (!to_bytes(text, source))
                {
                    ui::error(enc("Invalid text."));
                    return 0;
                }
                if (source.empty()) return 0;
                {
                    std::lock_guard<std::mutex> lock(job_mutex);
                    pending_source.swap(source);
                    job_pending = true;
                }
                busy = true;
                EnableWindow(execute_button, FALSE);
                job_changed.notify_one();
            }
            return 0;
        case load_id:
            load_script(window);
            return 0;
        case clear_id:
            SetWindowTextW(editor_box, L"");
            SetFocus(editor_box);
            return 0;
        }
        break;
    case ui_event:
    {
        auto* text = reinterpret_cast<std::wstring*>(lparam);
        if (text)
        {
            if (static_cast<event_kind>(wparam) == event_kind::error)
                show_error(window, *text);
            else
                append_output(*text);
            delete text;
        }
        if (static_cast<event_kind>(wparam) == event_kind::ready)
        {
            ready = true;
            EnableWindow(execute_button, TRUE);
        }
        if (static_cast<event_kind>(wparam) == event_kind::finished)
        {
            busy = false;
            EnableWindow(execute_button, ready);
        }
        return 0;
    }
    case WM_DESTROY:
    {
        {
            std::lock_guard<std::mutex> lock(window_mutex);
            main_window = nullptr;
        }
        {
            std::lock_guard<std::mutex> lock(job_mutex);
            stopping = true;
        }
        if (stop_event) SetEvent(stop_event);
        job_changed.notify_all();
        MSG pending = {};
        while (PeekMessageW(&pending, window, ui_event, ui_event, PM_REMOVE))
            delete reinterpret_cast<std::wstring*>(pending.lParam);
        if (code_font) { DeleteObject(code_font); code_font = nullptr; }
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(window, message, wparam, lparam);
}
}

namespace ui
{
void write(const std::string& text) { post_event(event_kind::output, text); }
void error(const std::string& text)
{
    std::wstring message = from_bytes(text);
    {
        std::lock_guard<std::mutex> lock(window_mutex);
        if (main_window)
        {
            auto* posted = new std::wstring(message);
            if (PostMessageW(main_window, ui_event, static_cast<WPARAM>(event_kind::error), reinterpret_cast<LPARAM>(posted))) return;
            delete posted;
        }
    }
    show_error(nullptr, message);
}
void writef(const char* format, ...)
{
    char buffer[2048] = {};
    va_list arguments;
    va_start(arguments, format);
    std::vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    write(buffer);
}
}

DWORD WINAPI ui_thread(LPVOID parameter)
{
    HMODULE module = static_cast<HMODULE>(parameter);
    WNDCLASSW type = {};
    type.lpfnWndProc = window_proc;
    type.hInstance = module;
    type.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    type.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    type.lpszClassName = L"No";
    if (!RegisterClassW(&type)) { ui::error(enc("Failed to create window")); SetEvent(window_created); return 0; }
    HWND window = CreateWindowExW(0, type.lpszClassName, L"", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 370, 400, nullptr, nullptr, module, nullptr);
    if (!window) { ui::error(enc("Failed to create window")); SetEvent(window_created); return 0; }
    {
        std::lock_guard<std::mutex> lock(window_mutex);
        main_window = window;
    }
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    SetFocus(editor_box);
    SetEvent(window_created);
    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0)
    {
        if ((message.hwnd == editor_box || message.hwnd == output_box) &&
            message.message == WM_KEYDOWN && message.wParam == 'A' &&
            (GetKeyState(VK_CONTROL) & 0x8000) && !(GetKeyState(VK_MENU) & 0x8000))
        {
            SendMessageW(message.hwnd, EM_SETSEL, 0, -1);
            continue;
        }
        if (!IsDialogMessageW(window, &message))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    return 0;
}

void _start(HMODULE module)
{
    static_assert(sizeof(void*) == 4, "build Win32");
    state_captured = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    window_created = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!state_captured || !stop_event || !window_created) { ui::error(enc("Failed to initialize")); return; }
    HANDLE thread = CreateThread(nullptr, 0, ui_thread, module, 0, nullptr);
    if (!thread) { ui::error(enc("Failed to create window")); return; }
    CloseHandle(thread);
    if (WaitForSingleObject(window_created, INFINITE) != WAIT_OBJECT_0) { ui::error(enc("Failed to initialize")); return; }
    {
        std::lock_guard<std::mutex> lock(window_mutex);
        if (!main_window) return;
    }
    execution_worker(nullptr);
}
