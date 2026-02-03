//go:build darwin

package keystroke

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>
#import <AppKit/AppKit.h>
#import <dispatch/dispatch.h>

// ============================================================================
// Clipboard Access via Main Thread
// ============================================================================
//
// NSPasteboard and other AppKit classes must be accessed from the main thread.
// Using dispatch_sync to the main queue ensures thread safety and avoids the
// "Collection was mutated while being enumerated" crash that occurs when
// multiple threads access NSPasteboard concurrently.
//
// ============================================================================

const char* getClipboardText() {
    __block char* result = NULL;

    if ([NSThread isMainThread]) {
        // Already on main thread, access directly
        @autoreleasepool {
            NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
            NSString *text = [pasteboard stringForType:NSPasteboardTypeString];
            if (text != nil) {
                result = strdup([text UTF8String]);
            }
        }
    } else {
        // Dispatch to main thread and wait
        dispatch_sync(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
                NSString *text = [pasteboard stringForType:NSPasteboardTypeString];
                if (text != nil) {
                    result = strdup([text UTF8String]);
                }
            }
        });
    }

    return result ? result : strdup("");
}

const char* getClipboardType() {
    __block const char* typeStr = "unknown";

    if ([NSThread isMainThread]) {
        @autoreleasepool {
            NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
            NSArray *types = [pasteboard types];
            if (types != nil) {
                if ([types containsObject:NSPasteboardTypeString]) {
                    typeStr = "text";
                } else if ([types containsObject:NSPasteboardTypePNG] ||
                           [types containsObject:NSPasteboardTypeTIFF]) {
                    typeStr = "image";
                } else if ([types containsObject:NSPasteboardTypeFileURL]) {
                    typeStr = "files";
                }
            }
        }
    } else {
        dispatch_sync(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
                NSArray *types = [pasteboard types];
                if (types != nil) {
                    if ([types containsObject:NSPasteboardTypeString]) {
                        typeStr = "text";
                    } else if ([types containsObject:NSPasteboardTypePNG] ||
                               [types containsObject:NSPasteboardTypeTIFF]) {
                        typeStr = "image";
                    } else if ([types containsObject:NSPasteboardTypeFileURL]) {
                        typeStr = "files";
                    }
                }
            }
        });
    }

    return strdup(typeStr);
}

// Note: Getting source app requires accessibility permissions and is complex
// For now, return empty string
const char* getClipboardSourceApp() {
    return strdup("");
}

// Free strdup'd memory - safe to call on any strdup'd string
void freeClipboardString(const char* str) {
    if (str != NULL) {
        free((void*)str);
    }
}
*/
import "C"

// darwinClipboardAccessor implements ClipboardAccessor for macOS.
type darwinClipboardAccessor struct{}

func newPlatformClipboardAccessor() ClipboardAccessor {
	return &darwinClipboardAccessor{}
}

func (d *darwinClipboardAccessor) GetText() (string, error) {
	cstr := C.getClipboardText()
	str := C.GoString(cstr)
	// Free the strdup'd memory from C
	C.freeClipboardString(cstr)
	return str, nil
}

func (d *darwinClipboardAccessor) GetContentType() string {
	cstr := C.getClipboardType()
	str := C.GoString(cstr)
	C.freeClipboardString(cstr)
	return str
}

func (d *darwinClipboardAccessor) GetSourceApp() string {
	cstr := C.getClipboardSourceApp()
	str := C.GoString(cstr)
	C.freeClipboardString(cstr)
	return str
}
