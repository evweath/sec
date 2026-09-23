// evw-tcc-reader — read sensitive-service rows from the macOS TCC databases.
//
// TCC.db sits behind Full Disk Access even for root. Granting FDA to a
// general interpreter (/usr/bin/python3, /usr/bin/sqlite3) would hand Full
// Disk Access to every script on the machine, so this helper exists to scope
// the grant to exactly one auditable operation: a fixed, read-only query over
// the system and user TCC databases. It accepts no SQL, no db path, no
// options:
//
//   evw-tcc-reader system   rows from /Library/Application Support/com.apple.TCC/TCC.db
//   evw-tcc-reader user     rows from /Users/evw/Library/Application Support/com.apple.TCC/TCC.db
//
// Output (pipe-separated, one row per grant):
//   service|client|client_type|auth_value|last_modified|indirect_object_identifier
// (auth_value: 0=denied 2=allowed 3=limited — same columns/order as
// tcc-audit.sh's fixed query, so callers can filter what they need.)
//
// Exit 0 on success (including 0 rows), 1 on read error, 64 on bad usage.
// Grant FDA in System Settings > Privacy & Security > Full Disk Access.
// Ad-hoc signed: TCC tracks it by cdhash — if the binary is ever rebuilt or
// reinstalled, redo the FDA grant.
//
// Build:  clang -O2 -Wall -o evw-tcc-reader evw-tcc-reader.c -lsqlite3
// Install: sudo install -m 755 -o root -g wheel evw-tcc-reader /usr/local/bin/

#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

static const char *DB_SYSTEM = "/Library/Application Support/com.apple.TCC/TCC.db";
static const char *DB_USER   = "/Users/evw/Library/Application Support/com.apple.TCC/TCC.db";

static const char *QUERY =
    "SELECT service,client,client_type,auth_value,last_modified,"
    "indirect_object_identifier FROM access WHERE service IN ("
    "'kTCCServiceScreenCapture','kTCCServiceAccessibility',"
    "'kTCCServiceListenEvent','kTCCServicePostEvent',"
    "'kTCCServiceCamera','kTCCServiceMicrophone') "
    "ORDER BY service,auth_value DESC;";

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "system") != 0 && strcmp(argv[1], "user") != 0)) {
        fprintf(stderr, "usage: %s system|user\n", argv[0]);
        return 64;
    }
    const char *path = strcmp(argv[1], "system") == 0 ? DB_SYSTEM : DB_USER;

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        fprintf(stderr, "open %s: %s\n", path, db ? sqlite3_errmsg(db) : "cannot open");
        if (db) sqlite3_close(db);
        return 1;
    }

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db, QUERY, -1, &st, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "prepare: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        for (int c = 0; c < 6; c++) {
            const unsigned char *t = sqlite3_column_text(st, c);
            printf("%s%s", c ? "|" : "", t ? (const char *)t : "");
        }
        printf("\n");
    }
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "step: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return rc == SQLITE_DONE ? 0 : 1;
}
