//go:build linux && cgo

package keystroke

/*
#cgo pkg-config: gtk+-3.0
#include <gtk/gtk.h>
#include <stdlib.h>

static int gtk_initialized = 0;

void ensure_gtk_init() {
    if (!gtk_initialized) {
        gtk_init(NULL, NULL);
        gtk_initialized = 1;
    }
}

char* get_clipboard_text_linux() {
    ensure_gtk_init();
    GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    if (clipboard == NULL) {
        return strdup("");
    }
    gchar *text = gtk_clipboard_wait_for_text(clipboard);
    if (text == NULL) {
        return strdup("");
    }
    char *result = strdup(text);
    g_free(text);
    return result;
}

const char* get_clipboard_type_linux() {
    ensure_gtk_init();
    GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    if (clipboard == NULL) {
        return "unknown";
    }

    if (gtk_clipboard_wait_is_text_available(clipboard)) {
        return "text";
    }
    if (gtk_clipboard_wait_is_image_available(clipboard)) {
        return "image";
    }
    if (gtk_clipboard_wait_is_uris_available(clipboard)) {
        return "files";
    }
    return "unknown";
}
*/
import "C"

import (
	"unsafe"
)

// linuxClipboardAccessor implements ClipboardAccessor for Linux.
type linuxClipboardAccessor struct{}

func newPlatformClipboardAccessor() ClipboardAccessor {
	return &linuxClipboardAccessor{}
}

func (l *linuxClipboardAccessor) GetText() (string, error) {
	cstr := C.get_clipboard_text_linux()
	defer C.free(unsafe.Pointer(cstr))
	return C.GoString(cstr), nil
}

func (l *linuxClipboardAccessor) GetContentType() string {
	return C.GoString(C.get_clipboard_type_linux())
}

func (l *linuxClipboardAccessor) GetSourceApp() string {
	// X11/Wayland don't easily expose clipboard source
	return ""
}
