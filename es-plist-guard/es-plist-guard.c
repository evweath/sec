//
// es-plist-guard.c
//
// Endpoint Security client that DENIES modifications to launchd's per-user
// disabled-services database:
//
//   /var/db/com.apple.xpc.launchd/disabled.501.plist   (and its /private twin)
//
// There is no ES_EVENT_TYPE_AUTH_WRITE — write(2) itself is notify-only.
// Modification is gated at the points the kernel does authorize:
//
//   AUTH_OPEN        — deny when the kernel FWRITE flag is set on the target
//                      (covers open(2) O_WRONLY/O_RDWR/O_TRUNC; respond via
//                      es_respond_flags_result: 0 = deny, UINT32_MAX = allow)
//   AUTH_CREATE      — create at the target path
//   AUTH_TRUNCATE    — truncate(2)/ftruncate(2) on the target
//   AUTH_RENAME      — rename onto the target (atomic-save path: launchd's
//                      plist serializer writes a temp file then renames over
//                      it — the critical case) or rename the target away
//   AUTH_UNLINK      — delete the target
//   AUTH_SETATTRLIST — chmod/chown/chflags on the target
//
// While this daemon runs, `launchctl enable/disable` for uid 501 still
// changes launchd's in-memory state but the change CANNOT be persisted.
// Unload the daemon to unfreeze. That is the point: it freezes the
// disabled-state database against whatever has been silently rewriting it
// (see evw-plist-monitor.sh, which watches the same file).
//
// Runtime requirements:
//   1. Signature with the restricted entitlement
//      com.apple.developer.endpoint-security.client — needs a paid Apple
//      Developer account with the Endpoint Security capability approved
//      by Apple (see README.md). Without it es_new_client() is refused.
//   2. Full Disk Access for the binary (TCC), same as eslogger.
//

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/fcntl.h>
#include <time.h>

#ifndef FREAD
#define FREAD 0x00000001
#endif
#ifndef FWRITE
#define FWRITE 0x00000002
#endif

static const char *kTargets[] = {
    "/var/db/com.apple.xpc.launchd/disabled.501.plist",
    "/private/var/db/com.apple.xpc.launchd/disabled.501.plist",
};
static const size_t kTargetCount = sizeof(kTargets) / sizeof(kTargets[0]);

static int tok_is_target(es_string_token_t p) {
    if (!p.data) return 0;
    for (size_t i = 0; i < kTargetCount; i++) {
        size_t tl = strlen(kTargets[i]);
        if (p.length == tl && memcmp(p.data, kTargets[i], tl) == 0) return 1;
    }
    return 0;
}

// create/rename to a NEW path report directory + filename separately; compose.
static int dest_is_target(es_file_t *dir, es_string_token_t fname) {
    if (!dir || !dir->path.data || !fname.data) return 0;
    char buf[4096];
    size_t dl = dir->path.length, fl = fname.length;
    if (dl + 1 + fl >= sizeof(buf)) return 0;
    memcpy(buf, dir->path.data, dl);
    buf[dl] = '/';
    memcpy(buf + dl + 1, fname.data, fl);
    buf[dl + 1 + fl] = '\0';
    for (size_t i = 0; i < kTargetCount; i++) {
        if (strcmp(buf, kTargets[i]) == 0) return 1;
    }
    return 0;
}

static int destination_is_target(es_destination_type_t type, es_file_t *existing,
                                 es_file_t *dir, es_string_token_t fname) {
    if (type == ES_DESTINATION_TYPE_NEW_PATH)
        return dest_is_target(dir, fname);
    return existing && tok_is_target(existing->path);
}

static void log_deny(const char *verb, const es_message_t *m) {
    char ts[32];
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tmv);
    fprintf(stderr, "%s DENY %s target=disabled.501.plist actor=%s pid=%d ppid=%d ruid=%d\n",
            ts, verb,
            m->process->executable ? m->process->executable->path.data : "?",
            audit_token_to_pid(m->process->audit_token),
            m->process->ppid,
            (int)audit_token_to_ruid(m->process->audit_token));
    fflush(stderr);
}

int main(void) {
    es_client_t *client = NULL;
    es_new_client_result_t res = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) {
        // AUTH_OPEN is answered with a flags mask (0 denies, UINT32_MAX allows)
        // and never cached — a cached mask could mis-deny later opens.
        if (m->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
            int deny = (m->event.open.fflag & FWRITE) && tok_is_target(m->event.open.file->path);
            if (deny) log_deny("open-for-write", m);
            es_respond_flags_result(c, m, deny ? 0 : UINT32_MAX, false);
            return;
        }

        const char *verb = NULL;
        switch (m->event_type) {
            case ES_EVENT_TYPE_AUTH_CREATE:
                if (destination_is_target(m->event.create.destination_type,
                                          m->event.create.destination.existing_file,
                                          m->event.create.destination.new_path.dir,
                                          m->event.create.destination.new_path.filename))
                    verb = "create";
                break;
            case ES_EVENT_TYPE_AUTH_RENAME:
                if (tok_is_target(m->event.rename.source->path))
                    verb = "rename-away";
                else if (destination_is_target(m->event.rename.destination_type,
                                               m->event.rename.destination.existing_file,
                                               m->event.rename.destination.new_path.dir,
                                               m->event.rename.destination.new_path.filename))
                    verb = "rename-over";
                break;
            case ES_EVENT_TYPE_AUTH_UNLINK:
                if (tok_is_target(m->event.unlink.target->path))
                    verb = "unlink";
                break;
            case ES_EVENT_TYPE_AUTH_TRUNCATE:
                if (tok_is_target(m->event.truncate.target->path))
                    verb = "truncate";
                break;
            case ES_EVENT_TYPE_AUTH_SETATTRLIST:
                if (tok_is_target(m->event.setattrlist.target->path))
                    verb = "setattrlist";
                break;
            default:
                break;
        }

        if (verb) {
            log_deny(verb, m);
            es_respond_auth_result(c, m, ES_AUTH_RESULT_DENY, false);
        } else {
            es_respond_auth_result(c, m, ES_AUTH_RESULT_ALLOW, false);
        }
    });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es-plist-guard: es_new_client failed (%d) — requires the signed "
                "com.apple.developer.endpoint-security.client entitlement and Full Disk "
                "Access. See README.md.\n", (int)res);
        return 1;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_TRUNCATE,
        ES_EVENT_TYPE_AUTH_SETATTRLIST,
    };
    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es-plist-guard: es_subscribe failed\n");
        return 1;
    }

    fprintf(stderr, "es-plist-guard: active — modifications to disabled.501.plist will be DENIED\n");
    dispatch_main();
    return 0;
}
