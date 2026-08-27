#!/usr/bin/env python3
"""
=============================================================================
 shopify_migrate.py  —  Shopify Store Migration Tool
=============================================================================

 USAGE:
   ./run_migration.sh                     # interactive group selector (default)
   ./run_migration.sh --all               # migrate everything, no prompts
   ./run_migration.sh --groups products collections customers
   ./run_migration.sh --dry-run           # preview only, no writes
   ./run_migration.sh --resume            # resume interrupted run
   ./run_migration.sh --validate          # post-migration QA report
   ./run_migration.sh --list              # list all groups and phases

 MIGRATION GROUPS (choose at runtime):
   products     — products, variants, images, metafields
   collections  — smart + manual collections, product-collection assignments
   customers    — customer records and addresses
   orders       — historical order archive (reference copy)
   content      — pages, blog posts, articles
   navigation   — menus and link trees
   discounts    — price rules and discount codes
   gift_cards   — outstanding gift card balances
   files        — store CDN files (logo, banners)
   redirects    — URL redirect rules (SEO)

 CREDENTIALS — set as environment variables before running:
   export SOURCE_SHOP="your-source.myshopify.com"
   export SOURCE_CLIENT_ID="..."
   export SOURCE_CLIENT_SECRET="..."
   export DEST_SHOP="your-dest.myshopify.com"
   export DEST_CLIENT_ID="..."
   export DEST_CLIENT_SECRET="..."

   # OR use legacy shpat_ tokens:
   export SOURCE_TOKEN="shpat_..."
   export DEST_TOKEN="shpat_..."

=============================================================================
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

import requests

# ── SSL certificate fix ───────────────────────────────────────────────────────
try:
    import certifi
    _SSL_VERIFY = certifi.where()
except ImportError:
    import ssl as _ssl_mod
    _cafile = _ssl_mod.get_default_verify_paths().cafile
    _SSL_VERIFY = _cafile if _cafile else True

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

CONFIG = {
    "source_shop":          os.environ.get("SOURCE_SHOP",          ""),
    "source_client_id":     os.environ.get("SOURCE_CLIENT_ID",     ""),
    "source_client_secret": os.environ.get("SOURCE_CLIENT_SECRET", ""),
    "source_token":         os.environ.get("SOURCE_TOKEN",         ""),
    "dest_shop":            os.environ.get("DEST_SHOP",            ""),
    "dest_client_id":       os.environ.get("DEST_CLIENT_ID",       ""),
    "dest_client_secret":   os.environ.get("DEST_CLIENT_SECRET",   ""),
    "dest_token":           os.environ.get("DEST_TOKEN",           ""),
    "api_version":          "2024-10",
    "request_delay":        0.5,
    "state_file":           "migration_state.json",
    "log_file":             "migration.log",
    "publish_products":     True,
    "max_retries":          5,
    # Set to a positive integer to limit metafield fetches (0 = unlimited)
    "metafields_limit":     0,
}

# ─────────────────────────────────────────────────────────────────────────────
# GROUP DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

GROUPS: Dict[str, Dict] = {
    "products":    {"label": "Products",     "emoji": "📦",
                    "description": "Products, variants, images, metafields",
                    "phases": ["products", "metafields"]},
    "collections": {"label": "Collections",  "emoji": "📁",
                    "description": "Smart + manual collections, assignments",
                    "phases": ["collections", "collects"]},
    "customers":   {"label": "Customers",    "emoji": "👥",
                    "description": "Customer records and addresses",
                    "phases": ["customers"]},
    "orders":      {"label": "Orders",       "emoji": "🧾",
                    "description": "Historical order archive",
                    "phases": ["orders"]},
    "content":     {"label": "Content",      "emoji": "📝",
                    "description": "Pages, blog posts, and articles",
                    "phases": ["pages", "blogs"]},
    "navigation":  {"label": "Navigation",   "emoji": "🗺️",
                    "description": "Menus and nested link trees",
                    "phases": ["navigation"]},
    "discounts":   {"label": "Discounts",    "emoji": "🏷️",
                    "description": "Price rules and discount codes",
                    "phases": ["price_rules"]},
    "gift_cards":  {"label": "Gift Cards",   "emoji": "🎁",
                    "description": "Outstanding gift card balances",
                    "phases": ["gift_cards"]},
    "files":       {"label": "Files",        "emoji": "🗂️",
                    "description": "Store CDN assets (logo, banners)",
                    "phases": ["files"]},
    "redirects":   {"label": "URL Redirects","emoji": "↪️",
                    "description": "URL redirect rules (important for SEO)",
                    "phases": ["redirects"]},
}

PHASE_ORDER = [
    "products", "metafields",
    "collections", "collects",
    "customers", "orders",
    "pages", "blogs",
    "redirects", "navigation",
    "price_rules", "gift_cards",
    "files",
]

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(CONFIG["log_file"]),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("migrate")

# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE GROUP SELECTOR
# ─────────────────────────────────────────────────────────────────────────────

def interactive_selector() -> List[str]:
    """Numbered toggle menu. Returns list of selected group keys."""
    group_keys = list(GROUPS.keys())
    selected   = set(group_keys)          # default: all on

    while True:
        print()
        print("  ┌──────────────────────────────────────────────────────────────┐")
        print("  │              SELECT MIGRATION GROUPS                         │")
        print("  │   Toggle with numbers. 'a'=all, 'n'=none. Enter=confirm.    │")
        print("  ├──────────────────────────────────────────────────────────────┤")
        for i, key in enumerate(group_keys, 1):
            g    = GROUPS[key]
            tick = "✓" if key in selected else " "
            desc = g["description"][:35]
            print(f"  │  [{tick}] {i:2d}.  {g['emoji']}  {g['label']:<15}  {desc:<35}  │")
        print("  ├──────────────────────────────────────────────────────────────┤")
        print("  │  Enter numbers to toggle (e.g. 1 3 5), 'a', 'n', or Enter  │")
        print("  └──────────────────────────────────────────────────────────────┘")

        try:
            raw = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.")
            sys.exit(0)

        if raw == "":
            if not selected:
                print("  ⚠️  Nothing selected. Pick at least one group.")
                continue
            break
        elif raw == "a":
            selected = set(group_keys)
        elif raw == "n":
            selected = set()
        else:
            for token in raw.replace(",", " ").split():
                try:
                    idx = int(token) - 1
                    if 0 <= idx < len(group_keys):
                        key = group_keys[idx]
                        selected.discard(key) if key in selected else selected.add(key)
                    else:
                        print(f"  ⚠️  {token} out of range (1-{len(group_keys)})")
                except ValueError:
                    print(f"  ⚠️  '{token}' is not a number")

    return [k for k in group_keys if k in selected]


def groups_to_phases(group_keys: List[str]) -> List[str]:
    wanted = {p for k in group_keys for p in GROUPS[k]["phases"]}
    return [p for p in PHASE_ORDER if p in wanted]


# ─────────────────────────────────────────────────────────────────────────────
# SHOPIFY CLIENT
# ─────────────────────────────────────────────────────────────────────────────

class ShopifyClient:

    def __init__(self, shop: str, token: str = "", api_version: str = "2024-10",
                 label: str = "", client_id: str = "", client_secret: str = ""):
        shop = shop.replace("https://", "").replace("http://", "").rstrip("/")
        if not shop.endswith(".myshopify.com"):
            shop = f"{shop}.myshopify.com"
        self.shop        = shop
        self.base        = f"https://{shop}/admin/api/{api_version}"
        self.api_version = api_version
        self.label       = label or shop
        self.delay       = CONFIG["request_delay"]
        self.max_retries = CONFIG["max_retries"]
        self.headers     = {"Content-Type": "application/json"}
        self._static_token     = token
        self._client_id        = client_id
        self._client_secret    = client_secret
        self._dynamic_token    = None
        self._token_expires_at = 0
        if not self._static_token and not (self._client_id and self._client_secret):
            raise ValueError(
                f"[{self.label}] No credentials.\n"
                f"  Set {label}_CLIENT_ID + {label}_CLIENT_SECRET, or {label}_TOKEN."
            )

    # ── Token ─────────────────────────────────────────────────────────────

    def _get_token(self) -> str:
        if self._static_token:
            return self._static_token
        if self._dynamic_token and time.time() < self._token_expires_at - 60:
            return self._dynamic_token

        log.info(f"[{self.label}] Requesting OAuth token ...")
        resp = requests.post(
            f"https://{self.shop}/admin/oauth/access_token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "client_credentials",
                  "client_id":  self._client_id,
                  "client_secret": self._client_secret},
            timeout=30, verify=_SSL_VERIFY,
        )
        if not resp.ok:
            body = resp.text[:500]
            if "shop_not_permitted" in body:
                raise RuntimeError(
                    f"\n[{self.label}] shop_not_permitted — app and store are in different orgs.\n"
                    f"  Fix: open {self.shop}/admin → Settings → Apps → Develop apps\n"
                    f"  → Build apps in Dev Dashboard → create app there → install on this store."
                )
            elif resp.status_code == 401:
                raise RuntimeError(
                    f"\n[{self.label}] 401 Unauthorized — wrong Client ID or Secret.\n"
                    f"  ID used: {self._client_id[:8]}...{self._client_id[-4:]}\n"
                    f"  Fix: dev.shopify.com/dashboard → app → Settings (LEFT sidebar)\n"
                    f"  → re-copy Client ID and Secret, and confirm app is installed."
                )
            elif resp.status_code == 404:
                raise RuntimeError(
                    f"\n[{self.label}] 404 — store '{self.shop}' not found.\n"
                    f"  Verify SOURCE_SHOP / DEST_SHOP is a valid .myshopify.com subdomain."
                )
            else:
                raise RuntimeError(
                    f"\n[{self.label}] Token failed {resp.status_code}: {body}"
                )

        data = resp.json()
        if "access_token" not in data:
            raise RuntimeError(f"[{self.label}] No access_token in response: {data}")
        self._dynamic_token    = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 86399)
        log.info(f"[{self.label}] Token obtained "
                 f"(expires in {data.get('expires_in', 86399)//3600:.0f}h)")
        return self._dynamic_token

    # ── HTTP ──────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base}{path}" if path.startswith("/") else path
        for attempt in range(self.max_retries):
            time.sleep(self.delay)
            hdrs = {**self.headers, "X-Shopify-Access-Token": self._get_token()}
            try:
                resp = requests.request(method, url, headers=hdrs,
                                        verify=_SSL_VERIFY, **kwargs)
            except requests.RequestException as exc:
                log.warning(f"[{self.label}] Network error attempt {attempt+1}: {exc}")
                time.sleep(2 ** attempt)
                continue
            if resp.status_code == 429:
                wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                log.warning(f"[{self.label}] Rate limited — waiting {wait:.1f}s")
                time.sleep(wait)
                continue
            if resp.status_code in (500, 502, 503, 504):
                log.warning(f"[{self.label}] Server error {resp.status_code} — retry")
                time.sleep(2 ** attempt)
                continue
            return resp
        raise RuntimeError(
            f"[{self.label}] Failed after {self.max_retries} attempts: {method} {url}"
        )

    def get(self, path: str, params: dict = None) -> dict:
        r = self._request("GET", path, params=params or {})
        r.raise_for_status(); return r.json()

    def post(self, path: str, data: dict) -> dict:
        r = self._request("POST", path, json=data)
        if r.status_code not in (200, 201):
            log.error(f"[{self.label}] POST {path} → {r.status_code}: {r.text[:300]}")
        r.raise_for_status(); return r.json()

    def put(self, path: str, data: dict) -> dict:
        r = self._request("PUT", path, json=data)
        r.raise_for_status(); return r.json()

    def delete(self, path: str):
        self._request("DELETE", path).raise_for_status()

    def paginate(self, path: str, resource_key: str,
                 params: dict = None) -> Generator:
        params = {**(params or {}), "limit": 250}
        url    = f"{self.base}{path}"
        while url:
            resp = self._request("GET", url, params=params)
            resp.raise_for_status()
            yield from resp.json().get(resource_key, [])
            link, url, params = resp.headers.get("Link", ""), None, {}
            for part in link.split(","):
                part = part.strip()
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>"); break

    def graphql(self, query: str, variables: dict = None) -> dict:
        r = self._request("POST", "/graphql.json",
                          json={"query": query, "variables": variables or {}})
        r.raise_for_status(); return r.json()

    def test_connection(self) -> bool:
        log.info(f"[{self.label}] Testing connection to {self.shop} ...")
        try:
            token = self._get_token()
        except RuntimeError as exc:
            log.error(str(exc)); return False
        try:
            resp = requests.get(
                f"https://{self.shop}/admin/api/{self.api_version}/shop.json",
                headers={"X-Shopify-Access-Token": token,
                         "Content-Type": "application/json"},
                verify=_SSL_VERIFY, timeout=15,
            )
            if resp.status_code == 200:
                name = resp.json().get("shop", {}).get("name", self.shop)
                log.info(f"[{self.label}] Connected to '{name}'"); return True
            elif resp.status_code == 401:
                log.error(
                    f"[{self.label}] 401 — token OK but API rejected it.\n"
                    f"  App is probably NOT installed on {self.shop}.\n"
                    f"  Fix: dev.shopify.com/dashboard → app → Home → Installs\n"
                    f"       → Install app → select {self.shop}"
                ); return False
            else:
                log.error(f"[{self.label}] API test {resp.status_code}: {resp.text[:200]}")
                return False
        except requests.RequestException as exc:
            log.error(f"[{self.label}] Network error: {exc}"); return False


# ─────────────────────────────────────────────────────────────────────────────
# MIGRATION STATE
# ─────────────────────────────────────────────────────────────────────────────

class MigrationState:

    def __init__(self, path: str):
        self.path = Path(path)
        self._s   = self._load()

    def _load(self):
        if self.path.exists():
            try: return json.loads(self.path.read_text())
            except Exception: pass
        return {"completed": [], "id_maps": {},
                "started_at": datetime.now(timezone.utc).isoformat()}

    def save(self):
        self.path.write_text(json.dumps(self._s, indent=2))

    def mark_complete(self, phase: str):
        if phase not in self._s["completed"]:
            self._s["completed"].append(phase)
        self.save()

    def is_complete(self, phase: str) -> bool:
        return phase in self._s["completed"]

    def set_id_map(self, ns: str, src_id: int, dst_id: int):
        self._s["id_maps"].setdefault(ns, {})[str(src_id)] = dst_id
        self.save()

    def get_dest_id(self, ns: str, src_id: int) -> Optional[int]:
        return self._s["id_maps"].get(ns, {}).get(str(src_id))

    def get_id_map(self, ns: str) -> dict:
        return self._s["id_maps"].get(ns, {})


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def strip_keys(d: dict, keys: List[str]) -> dict:
    return {k: v for k, v in d.items() if k not in keys}


# ─────────────────────────────────────────────────────────────────────────────
# MIGRATOR
# ─────────────────────────────────────────────────────────────────────────────

class Migrator:

    def __init__(self, src: ShopifyClient, dst: ShopifyClient,
                 state: MigrationState, dry_run: bool = False):
        self.src     = src
        self.dst     = dst
        self.state   = state
        self.dry_run = dry_run
        if dry_run:
            log.info("🔍  DRY RUN — reads from source, NO writes to destination")

    def _post(self, path: str, data: dict) -> Optional[dict]:
        return {"id": 0} if self.dry_run else self.dst.post(path, data)

    def _put(self, path: str, data: dict) -> Optional[dict]:
        return {} if self.dry_run else self.dst.put(path, data)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1 — PRODUCTS
    # ══════════════════════════════════════════════════════════════════════

    def migrate_products(self):
        phase = "products"
        if self.state.is_complete(phase):
            log.info("⏭  Products already migrated — skipping"); return
        log.info("━" * 60)
        log.info("📦  PHASE 1 — Products")
        log.info("━" * 60)

        strip    = ["id", "admin_graphql_api_id", "created_at", "updated_at",
                    "published_at", "image"]
        products = list(self.src.paginate("/products.json", "products"))
        total    = len(products)
        log.info(f"  Found {total} products")
        ok = errors = 0

        for n, p in enumerate(products, 1):
            src_id  = p["id"]
            title   = p.get("title", "?")
            payload = strip_keys(p, strip)
            payload["variants"] = [
                strip_keys(v, ["id", "product_id", "admin_graphql_api_id",
                               "created_at", "updated_at", "image_id"])
                for v in payload.get("variants", [])
            ]
            payload["images"] = [
                {"src": img["src"], "alt": img.get("alt", ""),
                 "position": img.get("position", 1)}
                for img in payload.get("images", [])
            ]
            payload["published"] = CONFIG["publish_products"]
            try:
                result  = self._post("/products.json", {"product": payload})
                dest_id = result.get("product", {}).get("id", 0)
                self.state.set_id_map("products", src_id, dest_id)
                log.info(f"  [{n}/{total}] ✅  {title[:55]}")
                ok += 1
            except Exception as exc:
                log.error(f"  [{n}/{total}] ❌  {title[:55]}: {exc}")
                errors += 1

        log.info(f"\n  Products: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2 — METAFIELDS  (freeze fix: progress every 10 products)
    # ══════════════════════════════════════════════════════════════════════

    def migrate_metafields(self):
        phase = "metafields"
        if self.state.is_complete(phase):
            log.info("⏭  Metafields already migrated — skipping"); return
        log.info("━" * 60)
        log.info("🔧  PHASE 2 — Product Metafields")
        log.info("━" * 60)

        id_map = self.state.get_id_map("products")
        if not id_map:
            log.warning("  No product ID map — run Products phase first")
            self.state.mark_complete(phase); return

        entries = list(id_map.items())
        limit   = CONFIG.get("metafields_limit", 0)
        if limit and limit < len(entries):
            log.info(f"  metafields_limit={limit} — processing first {limit} products")
            entries = entries[:limit]

        total    = len(entries)
        ok = errors = skipped = 0
        log.info(f"  Fetching metafields for {total} products "
                 f"(progress shown every 10) ...")

        for n, (src_id_str, dest_id) in enumerate(entries, 1):
            src_id = int(src_id_str)

            # Progress update every 10 so terminal never looks frozen
            if n == 1 or n % 10 == 0 or n == total:
                log.info(f"  [{n}/{total}] checking product {src_id} ...")

            try:
                mfs = list(self.src.paginate(
                    f"/products/{src_id}/metafields.json", "metafields"))
            except Exception as exc:
                log.warning(f"  Could not fetch metafields for product {src_id}: {exc}")
                skipped += 1; continue

            for mf in mfs:
                try:
                    self._post(f"/products/{dest_id}/metafields.json",
                               {"metafield": {
                                   "namespace": mf["namespace"],
                                   "key":       mf["key"],
                                   "value":     mf["value"],
                                   "type":      mf.get("type", "single_line_text_field"),
                               }})
                    ok += 1
                except Exception as exc:
                    log.error(f"  ❌  {mf.get('namespace')}.{mf.get('key')} "
                              f"(product {src_id}): {exc}")
                    errors += 1

        log.info(f"\n  Metafields: {ok} migrated, {skipped} products skipped, "
                 f"{errors} errors")
        self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3 — COLLECTIONS
    # ══════════════════════════════════════════════════════════════════════

    def migrate_collections(self):
        phase = "collections"
        if self.state.is_complete(phase):
            log.info("⏭  Collections already migrated — skipping"); return
        log.info("━" * 60)
        log.info("📁  PHASE 3 — Collections")
        log.info("━" * 60)

        ok = errors = 0

        smart = list(self.src.paginate("/smart_collections.json",
                                       "smart_collections"))
        log.info(f"  Found {len(smart)} smart collections")
        strip_s = ["id", "admin_graphql_api_id", "updated_at", "published_at",
                   "sort_order", "published_scope"]
        for n, col in enumerate(smart, 1):
            src_id  = col["id"]
            payload = strip_keys(col, strip_s)
            payload.pop("image", None)
            if col.get("image", {}).get("src"):
                payload["image"] = {"src": col["image"]["src"]}
            try:
                r = self._post("/smart_collections.json",
                               {"smart_collection": payload})
                self.state.set_id_map("smart_collections", src_id,
                                      r.get("smart_collection", {}).get("id", 0))
                log.info(f"  [{n}/{len(smart)}] ✅  [Smart] {col.get('title','')[:50]}")
                ok += 1
            except Exception as exc:
                log.error(f"  [{n}/{len(smart)}] ❌  {col.get('title','')[:50]}: {exc}")
                errors += 1

        manual = list(self.src.paginate("/custom_collections.json",
                                        "custom_collections"))
        log.info(f"  Found {len(manual)} manual collections")
        strip_m = ["id", "admin_graphql_api_id", "published_at",
                   "updated_at", "published_scope"]
        for n, col in enumerate(manual, 1):
            src_id  = col["id"]
            payload = strip_keys(col, strip_m)
            payload.pop("image", None)
            if col.get("image", {}).get("src"):
                payload["image"] = {"src": col["image"]["src"]}
            try:
                r = self._post("/custom_collections.json",
                               {"custom_collection": payload})
                self.state.set_id_map("custom_collections", src_id,
                                      r.get("custom_collection", {}).get("id", 0))
                log.info(f"  [{n}/{len(manual)}] ✅  [Manual] {col.get('title','')[:50]}")
                ok += 1
            except Exception as exc:
                log.error(f"  [{n}/{len(manual)}] ❌  {col.get('title','')[:50]}: {exc}")
                errors += 1

        log.info(f"\n  Collections: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4 — COLLECTS
    # ══════════════════════════════════════════════════════════════════════

    def migrate_collects(self):
        phase = "collects"
        if self.state.is_complete(phase):
            log.info("⏭  Collects already migrated — skipping"); return
        log.info("━" * 60)
        log.info("🔗  PHASE 4 — Product ↔ Collection Assignments")
        log.info("━" * 60)

        pmap = self.state.get_id_map("products")
        cmap = {**self.state.get_id_map("custom_collections"),
                **self.state.get_id_map("smart_collections")}

        # ── If ID maps are empty (e.g. resuming after a fresh run that already
        #    migrated products/collections), rebuild them by matching handles ──
        if not pmap:
            log.info("  Product ID map empty — rebuilding from handle matching ...")
            src_products = {p["handle"]: p["id"]
                            for p in self.src.paginate("/products.json", "products")}
            dst_products = {p["handle"]: p["id"]
                            for p in self.dst.paginate("/products.json", "products")}
            rebuilt = 0
            for handle, src_id in src_products.items():
                dst_id = dst_products.get(handle)
                if dst_id:
                    self.state.set_id_map("products", src_id, dst_id)
                    pmap[str(src_id)] = dst_id
                    rebuilt += 1
            log.info(f"  Rebuilt {rebuilt} product ID mappings from handles")

        if not cmap:
            log.info("  Collection ID map empty — rebuilding from handle matching ...")
            src_smart  = {c["handle"]: c["id"]
                          for c in self.src.paginate("/smart_collections.json",
                                                      "smart_collections")}
            dst_smart  = {c["handle"]: c["id"]
                          for c in self.dst.paginate("/smart_collections.json",
                                                      "smart_collections")}
            src_manual = {c["handle"]: c["id"]
                          for c in self.src.paginate("/custom_collections.json",
                                                      "custom_collections")}
            dst_manual = {c["handle"]: c["id"]
                          for c in self.dst.paginate("/custom_collections.json",
                                                      "custom_collections")}
            rebuilt = 0
            for handle, src_id in src_smart.items():
                dst_id = dst_smart.get(handle)
                if dst_id:
                    self.state.set_id_map("smart_collections", src_id, dst_id)
                    cmap[str(src_id)] = dst_id
                    rebuilt += 1
            for handle, src_id in src_manual.items():
                dst_id = dst_manual.get(handle)
                if dst_id:
                    self.state.set_id_map("custom_collections", src_id, dst_id)
                    cmap[str(src_id)] = dst_id
                    rebuilt += 1
            log.info(f"  Rebuilt {rebuilt} collection ID mappings from handles")

        items = list(self.src.paginate("/collects.json", "collects"))
        total = len(items)
        log.info(f"  Found {total} collect relationships")
        ok = skipped = errors = 0

        for n, c in enumerate(items, 1):
            dp = pmap.get(str(c["product_id"]))
            dc = cmap.get(str(c["collection_id"]))
            if not dp or not dc:
                skipped += 1; continue
            try:
                self._post("/collects.json",
                           {"collect": {"product_id": dp, "collection_id": dc}})
                ok += 1
            except Exception as exc:
                if "already" in str(exc).lower():
                    ok += 1
                else:
                    log.error(f"  ❌  {c['product_id']}→{c['collection_id']}: {exc}")
                    errors += 1
            if n % 50 == 0 or n == total:
                log.info(f"  Progress [{n}/{total}] ...")

        log.info(f"\n  Collects: {ok} assigned, {skipped} skipped, {errors} errors")
        if skipped > 0:
            log.warning(f"  ⚠️  {skipped} collects skipped — product or collection "
                        f"not found in ID map. These products may not appear in "
                        f"their collections on the destination store.")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 5 — CUSTOMERS
    # ══════════════════════════════════════════════════════════════════════

    def migrate_customers(self):
        phase = "customers"
        if self.state.is_complete(phase):
            log.info("⏭  Customers already migrated — skipping"); return
        log.info("━" * 60)
        log.info("👥  PHASE 5 — Customers")
        log.info("━" * 60)

        strip = ["id", "admin_graphql_api_id", "created_at", "updated_at",
                 "last_order_id", "last_order_name", "orders_count",
                 "total_spent", "currency"]
        customers = list(self.src.paginate("/customers.json", "customers"))
        total     = len(customers)
        log.info(f"  Found {total} customers")
        ok = errors = 0

        for n, cust in enumerate(customers, 1):
            src_id = cust["id"]
            # email can be None for phone-only customers — guard every use
            email  = (cust.get("email") or f"no-email-id-{src_id}")
            payload = strip_keys(cust, strip)
            payload.pop("password", None)
            payload["addresses"] = [
                strip_keys(a, ["id", "customer_id", "created_at", "updated_at"])
                for a in payload.get("addresses", [])
            ]
            payload["send_email_invite"]  = False
            payload["send_email_welcome"] = False
            try:
                r = self._post("/customers.json", {"customer": payload})
                self.state.set_id_map("customers", src_id,
                                      r.get("customer", {}).get("id", 0))
                log.info(f"  [{n}/{total}] ✅  {email[:50]}")
                ok += 1
            except Exception as exc:
                if "already" in str(exc).lower() or "422" in str(exc):
                    log.info(f"  [{n}/{total}] ⚠️  {email[:50]} — already exists")
                    ok += 1
                else:
                    log.error(f"  [{n}/{total}] ❌  {email[:50]}: {exc}")
                    errors += 1

        log.info(f"\n  Customers: {ok} migrated, {errors} errors")
        log.info("  ⚠️  Customers must reset passwords after migration.")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 6 — ORDERS
    # ══════════════════════════════════════════════════════════════════════

    def migrate_orders(self):
        phase = "orders"
        if self.state.is_complete(phase):
            log.info("⏭  Orders already exported — skipping"); return
        log.info("━" * 60)
        log.info("🧾  PHASE 6 — Orders (export + archive)")
        log.info("━" * 60)

        orders = list(self.src.paginate("/orders.json", "orders",
                                        params={"status": "any"}))
        total  = len(orders)
        log.info(f"  Found {total} orders")
        Path("orders_export.json").write_text(json.dumps(orders, indent=2))
        log.info("  💾  Full order history saved to orders_export.json")

        customer_map = self.state.get_id_map("customers")
        ok = errors  = 0

        for n, order in enumerate(orders, 1):
            name  = order.get("name", f"#{order['id']}")
            items = [
                {"title": i.get("title", "Imported item"),
                 "quantity": i.get("quantity", 1),
                 "price": i.get("price", "0.00"),
                 "requires_shipping": i.get("requires_shipping", True),
                 "taxable": i.get("taxable", True)}
                for i in order.get("line_items", [])
            ]
            if not items: continue

            draft = {
                "line_items": items,
                "note": (f"[MIGRATED] {name} | "
                         f"date: {order.get('created_at')} | "
                         f"total: {order.get('total_price')} {order.get('currency')}"),
                "tags": f"migrated,source-{order['id']}",
            }
            src_cust = (order.get("customer") or {}).get("id")
            if src_cust and customer_map.get(str(src_cust)):
                draft["customer"] = {"id": customer_map[str(src_cust)]}
            if order.get("shipping_address"):
                draft["shipping_address"] = strip_keys(
                    order["shipping_address"], ["id"])

            try:
                r        = self._post("/draft_orders.json", {"draft_order": draft})
                draft_id = r.get("draft_order", {}).get("id", 0)
                if draft_id and not self.dry_run:
                    try:
                        self.dst.put(f"/draft_orders/{draft_id}.json",
                                     {"draft_order": {"id": draft_id,
                                                       "status": "completed"}})
                    except Exception:
                        pass
                ok += 1
            except Exception as exc:
                log.error(f"  [{n}/{total}] ❌  {name}: {exc}")
                errors += 1

            if n % 25 == 0 or n == total:
                log.info(f"  Progress [{n}/{total}] ...")

        log.info(f"\n  Orders: {ok} archived, {errors} errors")
        self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 7 — PAGES
    # ══════════════════════════════════════════════════════════════════════

    def migrate_pages(self):
        phase = "pages"
        if self.state.is_complete(phase):
            log.info("⏭  Pages already migrated — skipping"); return
        log.info("━" * 60)
        log.info("📝  PHASE 7 — Content Pages")
        log.info("━" * 60)

        strip = ["id", "admin_graphql_api_id", "created_at", "updated_at", "shop_id"]
        pages = list(self.src.paginate("/pages.json", "pages"))
        total = len(pages)
        log.info(f"  Found {total} pages")
        ok = errors = 0

        for n, page in enumerate(pages, 1):
            src_id = page["id"]
            title  = page.get("title", "?")
            try:
                r = self._post("/pages.json", {"page": strip_keys(page, strip)})
                self.state.set_id_map("pages", src_id, r.get("page", {}).get("id", 0))
                log.info(f"  [{n}/{total}] ✅  {title[:55]}")
                ok += 1
            except Exception as exc:
                log.error(f"  [{n}/{total}] ❌  {title[:55]}: {exc}")
                errors += 1

        log.info(f"\n  Pages: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 8 — BLOGS + ARTICLES
    # ══════════════════════════════════════════════════════════════════════

    def migrate_blogs(self):
        phase = "blogs"
        if self.state.is_complete(phase):
            log.info("⏭  Blogs already migrated — skipping"); return
        log.info("━" * 60)
        log.info("✍️   PHASE 8 — Blogs + Articles")
        log.info("━" * 60)

        strip_b = ["id", "admin_graphql_api_id", "created_at", "updated_at"]
        strip_a = ["id", "admin_graphql_api_id", "blog_id",
                   "created_at", "updated_at", "user_id"]
        blogs   = list(self.src.paginate("/blogs.json", "blogs"))
        log.info(f"  Found {len(blogs)} blogs")
        ok = errors = 0

        for blog in blogs:
            src_bid = blog["id"]
            try:
                r        = self._post("/blogs.json",
                                       {"blog": strip_keys(blog, strip_b)})
                dest_bid = r.get("blog", {}).get("id", 0)
                self.state.set_id_map("blogs", src_bid, dest_bid)
                log.info(f"  ✅  Blog: {blog.get('title','')}")
            except Exception as exc:
                log.error(f"  ❌  Blog {blog.get('title','')}: {exc}")
                errors += 1; continue

            arts  = list(self.src.paginate(
                f"/blogs/{src_bid}/articles.json", "articles"))
            log.info(f"      → {len(arts)} articles")

            for n, art in enumerate(arts, 1):
                payload = strip_keys(art, strip_a)
                if art.get("image", {}).get("src"):
                    payload["image"] = {"src": art["image"]["src"]}
                else:
                    payload.pop("image", None)
                try:
                    r2 = self._post(f"/blogs/{dest_bid}/articles.json",
                                    {"article": payload})
                    self.state.set_id_map("articles", art["id"],
                                          r2.get("article", {}).get("id", 0))
                    log.info(f"      [{n}/{len(arts)}] ✅  {art.get('title','')[:50]}")
                    ok += 1
                except Exception as exc:
                    log.error(f"      [{n}/{len(arts)}] ❌  "
                              f"{art.get('title','')[:50]}: {exc}")
                    errors += 1

        log.info(f"\n  Articles: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 9 — REDIRECTS
    # ══════════════════════════════════════════════════════════════════════

    def migrate_redirects(self):
        phase = "redirects"
        if self.state.is_complete(phase):
            log.info("⏭  Redirects already migrated — skipping"); return
        log.info("━" * 60)
        log.info("↪️   PHASE 9 — URL Redirects")
        log.info("━" * 60)

        items = list(self.src.paginate("/redirects.json", "redirects"))
        total = len(items)
        log.info(f"  Found {total} redirects")
        ok = errors = 0

        for n, r in enumerate(items, 1):
            try:
                self._post("/redirects.json",
                           {"redirect": {"path": r["path"], "target": r["target"]}})
                ok += 1
            except Exception as exc:
                if "already" in str(exc).lower():
                    ok += 1
                else:
                    log.error(f"  ❌  {r['path']}: {exc}")
                    errors += 1
            if n % 50 == 0 or n == total:
                log.info(f"  Progress [{n}/{total}] ...")

        log.info(f"\n  Redirects: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 10 — NAVIGATION
    # ══════════════════════════════════════════════════════════════════════

    def migrate_navigation(self):
        phase = "navigation"
        if self.state.is_complete(phase):
            log.info("⏭  Navigation already migrated — skipping"); return
        log.info("━" * 60)
        log.info("🗺️   PHASE 10 — Navigation Menus")
        log.info("━" * 60)

        try:
            menus = self.src.get("/menus.json").get("menus", [])
        except Exception as exc:
            log.warning(f"  Could not fetch menus: {exc}")
            self.state.mark_complete(phase); return

        log.info(f"  Found {len(menus)} menus")

        def clean(items):
            return [{"title": i.get("title", ""), "type": i.get("type", "http"),
                     "url": i.get("url", "/"), "items": clean(i.get("items", []))}
                    for i in items]

        ok = errors = 0
        for menu in menus:
            payload = {"title": menu.get("title", ""),
                       "handle": menu.get("handle", ""),
                       "items": clean(menu.get("items", []))}
            try:
                self._post("/menus.json", {"menu": payload})
                log.info(f"  ✅  Menu: {menu.get('title')}")
                ok += 1
            except Exception as exc:
                try:
                    existing = self.dst.get("/menus.json").get("menus", [])
                    match    = next((m for m in existing
                                     if m.get("handle") == menu.get("handle")), None)
                    if match:
                        self._put(f"/menus/{match['id']}.json",
                                  {"menu": {**payload, "id": match["id"]}})
                        ok += 1
                    else:
                        raise exc
                except Exception as exc2:
                    log.error(f"  ❌  Menu {menu.get('title')}: {exc2}")
                    errors += 1

        log.info(f"\n  Menus: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 11 — PRICE RULES + DISCOUNT CODES
    # ══════════════════════════════════════════════════════════════════════

    def migrate_price_rules(self):
        phase = "price_rules"
        if self.state.is_complete(phase):
            log.info("⏭  Price rules already migrated — skipping"); return
        log.info("━" * 60)
        log.info("🏷️   PHASE 11 — Price Rules + Discount Codes")
        log.info("━" * 60)

        strip = ["id", "admin_graphql_api_id", "created_at", "updated_at",
                 "usage_count", "allocation_limit"]
        rules = list(self.src.paginate("/price_rules.json", "price_rules"))
        total = len(rules)
        log.info(f"  Found {total} price rules")
        ok = errors = 0

        for n, rule in enumerate(rules, 1):
            src_rid = rule["id"]
            title   = rule.get("title", "?")
            try:
                codes = list(self.src.paginate(
                    f"/price_rules/{src_rid}/discount_codes.json",
                    "discount_codes"))
            except Exception:
                codes = []
            try:
                r    = self._post("/price_rules.json",
                                   {"price_rule": strip_keys(rule, strip)})
                drid = r.get("price_rule", {}).get("id", 0)
                for code in codes:
                    try:
                        self._post(f"/price_rules/{drid}/discount_codes.json",
                                   {"discount_code": {"code": code.get("code", "")}})
                    except Exception:
                        pass
                log.info(f"  [{n}/{total}] ✅  {title[:50]} ({len(codes)} code(s))")
                ok += 1
            except Exception as exc:
                log.error(f"  [{n}/{total}] ❌  {title[:50]}: {exc}")
                errors += 1

        log.info(f"\n  Price rules: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 12 — GIFT CARDS
    # ══════════════════════════════════════════════════════════════════════

    def migrate_gift_cards(self):
        phase = "gift_cards"
        if self.state.is_complete(phase):
            log.info("⏭  Gift cards already migrated — skipping"); return
        log.info("━" * 60)
        log.info("🎁  PHASE 12 — Gift Cards")
        log.info("━" * 60)

        try:
            gcs = list(self.src.paginate("/gift_cards.json", "gift_cards",
                                          params={"status": "enabled"}))
        except Exception as exc:
            log.warning(f"  Gift cards not accessible (may need Shopify Plus): {exc}")
            self.state.mark_complete(phase); return

        active       = [g for g in gcs if float(g.get("balance", 0)) > 0]
        cmap         = self.state.get_id_map("customers")
        log.info(f"  Found {len(active)} gift cards with balance")
        ok = errors  = 0

        for n, gc in enumerate(active, 1):
            payload = {"gift_card": {
                "code":          gc.get("masked_code", gc.get("code")),
                "initial_value": gc.get("balance"),
                "note":          (gc.get("note") or "") +
                                  f" [migrated, src id: {gc['id']}]",
            }}
            dc = cmap.get(str(gc.get("customer_id", "")))
            if dc:
                payload["gift_card"]["customer_id"] = dc
            try:
                self._post("/gift_cards.json", payload); ok += 1
            except Exception as exc:
                log.error(f"  [{n}] ❌  GC {gc['id']}: {exc}"); errors += 1

        log.info(f"\n  Gift cards: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 13 — FILES (GraphQL Files API)
    # ══════════════════════════════════════════════════════════════════════

    def migrate_files(self):
        phase = "files"
        if self.state.is_complete(phase):
            log.info("⏭  Files already migrated — skipping"); return
        log.info("━" * 60)
        log.info("🗂️   PHASE 13 — Store Files")
        log.info("━" * 60)

        query = """
        query getFiles($cursor: String) {
          files(first: 50, after: $cursor) {
            pageInfo { hasNextPage endCursor }
            nodes {
              ... on MediaImage { id alt image { url } }
              ... on GenericFile { id alt url }
            }
          }
        }"""

        files = []; cursor = None
        while True:
            result    = self.src.graphql(query, {"cursor": cursor})
            page      = result.get("data", {}).get("files", {})
            files.extend(page.get("nodes", []))
            page_info = page.get("pageInfo", {})
            if not page_info.get("hasNextPage"): break
            cursor = page_info.get("endCursor")

        log.info(f"  Found {len(files)} store files")

        mutation = """
        mutation fileCreate($files: [FileCreateInput!]!) {
          fileCreate(files: $files) {
            files {
              ... on MediaImage { id }
              ... on GenericFile { id }
            }
            userErrors { field message }
          }
        }"""

        ok = errors = 0
        for n, f in enumerate(files, 1):
            url = ((f.get("image") or {}).get("url") or f.get("url"))
            if not url: continue
            url = url.split("?")[0]
            try:
                r    = self.dst.graphql(mutation, {"files": [{
                    "originalSource": url,
                    "alt":            f.get("alt", ""),
                    "contentType":    "IMAGE" if "image" in f else "FILE",
                }]})
                errs = (r.get("data", {}).get("fileCreate", {})
                         .get("userErrors", []))
                if errs:
                    log.warning(f"  [{n}] ⚠️  {url[-50:]}: {errs}")
                else:
                    log.info(f"  [{n}/{len(files)}] ✅  {url[-55:]}")
                ok += 1
            except Exception as exc:
                log.error(f"  [{n}] ❌  {url[-50:]}: {exc}"); errors += 1

        log.info(f"\n  Files: {ok} migrated, {errors} errors")
        if errors == 0:
            self.state.mark_complete(phase)

    # ══════════════════════════════════════════════════════════════════════
    # SEO REDIRECT GENERATOR
    # ══════════════════════════════════════════════════════════════════════

    def generate_seo_redirects(self):
        log.info("━" * 60)
        log.info("🔍  SEO — generating redirects for handle mismatches")
        log.info("━" * 60)
        redirects = []

        try:
            sp = {p["id"]: p["handle"]
                  for p in self.src.paginate("/products.json", "products")}
            dp = {p["id"]: p["handle"]
                  for p in self.dst.paginate("/products.json", "products")}
            for sid, did in self.state.get_id_map("products").items():
                sh, dh = sp.get(int(sid)), dp.get(did)
                if sh and dh and sh != dh:
                    redirects.append({"path": f"/products/{sh}",
                                       "target": f"/products/{dh}"})
        except Exception:
            pass

        ok = 0
        log.info(f"  Found {len(redirects)} handle mismatches")
        for r in redirects:
            try:
                self._post("/redirects.json", {"redirect": r}); ok += 1
                log.info(f"  ↪️  {r['path']} → {r['target']}")
            except Exception:
                pass
        log.info(f"  SEO redirects created: {ok}")

    # ══════════════════════════════════════════════════════════════════════
    # VALIDATION REPORT
    # ══════════════════════════════════════════════════════════════════════

    def validate(self):
        log.info("")
        log.info("═" * 60)
        log.info("🔍  POST-MIGRATION VALIDATION REPORT")
        log.info("═" * 60)
        checks = [
            ("Products",           "/products/count.json"),
            ("Customers",          "/customers/count.json"),
            ("Pages",              "/pages/count.json"),
            ("Blogs",              "/blogs/count.json"),
            ("Smart Collections",  "/smart_collections/count.json"),
            ("Custom Collections", "/custom_collections/count.json"),
            ("Redirects",          "/redirects/count.json"),
            ("Price Rules",        "/price_rules/count.json"),
        ]
        all_pass = True
        for label, path in checks:
            try:
                sn = self.src.get(path).get("count", 0)
                dn = self.dst.get(path).get("count", 0)
                icon = "✅" if dn >= sn else "⚠️ "
                if dn < sn: all_pass = False
                log.info(f"  {icon}  {label:<25} source:{sn:>5}   dest:{dn:>5}   "
                         f"diff:{dn-sn:+d}")
            except Exception as exc:
                log.warning(f"  ❓  {label:<25} {exc}")
        log.info("")
        if all_pass:
            log.info("  🎉  All counts match or exceed source!")
        else:
            log.info("  ⚠️   Some counts are lower — review migration.log")
        log.info("═" * 60)

    def print_manual_steps(self):
        log.info("")
        log.info("═" * 60)
        log.info("📋  REMAINING MANUAL STEPS (cannot be automated)")
        log.info("═" * 60)
        for i, (loc, inst) in enumerate([
            ("Payments",  "Re-connect Shopify Payments & PayPal. Re-verify business identity."),
            ("Markets",   "Re-enable international markets and currency conversion."),
            ("Shipping",  "Recreate shipping zones, rates, and freight profiles."),
            ("Taxes",     "Re-register tax nexus states. Enable automatic tax calculation."),
            ("Checkout",  "Re-configure checkout branding and notification email templates."),
            ("Theme",     "Re-enter all Theme Customizer settings (logo, colors, sections)."),
            ("Apps",      "Re-install all apps. Update API keys in external integrations."),
            ("Customers", "Send bulk password reset email to all migrated customers."),
            ("DNS",       "Transfer custom domain DNS to destination store (LAST STEP)."),
            ("GSC",       "Verify ownership in Google Search Console. Submit new sitemap."),
        ], 1):
            log.info(f"\n  [{i:02d}]  📍 {loc}")
            log.info(f"       {inst}")
        log.info("═" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE DISPATCH
# ─────────────────────────────────────────────────────────────────────────────

PHASE_METHODS = {
    "products":    "migrate_products",
    "metafields":  "migrate_metafields",
    "collections": "migrate_collections",
    "collects":    "migrate_collects",
    "customers":   "migrate_customers",
    "orders":      "migrate_orders",
    "pages":       "migrate_pages",
    "blogs":       "migrate_blogs",
    "redirects":   "migrate_redirects",
    "navigation":  "migrate_navigation",
    "price_rules": "migrate_price_rules",
    "gift_cards":  "migrate_gift_cards",
    "files":       "migrate_files",
}

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Shopify Store Migration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Groups: " + ", ".join(GROUPS.keys()),
    )
    p.add_argument("--all", action="store_true",
                   help="Migrate all groups without prompting")
    p.add_argument("--groups", nargs="+", choices=list(GROUPS.keys()),
                   metavar="GROUP", help="Specific groups to migrate")
    p.add_argument("--dry-run", action="store_true",
                   help="Read source, no writes to destination")
    p.add_argument("--resume", action="store_true",
                   help="Resume an interrupted run")
    p.add_argument("--validate", action="store_true",
                   help="Run QA report only")
    p.add_argument("--generate-redirects", action="store_true",
                   help="Generate SEO redirects for handle mismatches")
    p.add_argument("--list", action="store_true",
                   help="List all groups and phases then exit")
    p.add_argument("--source-shop",   default=None)
    p.add_argument("--source-token",  default=None)
    p.add_argument("--dest-shop",     default=None)
    p.add_argument("--dest-token",    default=None)
    return p.parse_args()


def validate_config(cfg):
    errors = []
    for key in ("source_shop", "dest_shop"):
        if not cfg.get(key, "").strip():
            errors.append(f"  {key} is not set")
    for prefix, label in (("source", "SOURCE"), ("dest", "DESTINATION")):
        has_tok   = bool(cfg.get(f"{prefix}_token", "").strip())
        has_oauth = bool(cfg.get(f"{prefix}_client_id", "").strip() and
                         cfg.get(f"{prefix}_client_secret", "").strip())
        if not has_tok and not has_oauth:
            errors.append(
                f"  {label}: no credentials. "
                f"Set {label}_CLIENT_ID + {label}_CLIENT_SECRET, "
                f"or {label}_TOKEN."
            )
    if cfg.get("source_shop") == cfg.get("dest_shop"):
        errors.append("  source_shop and dest_shop are the same store")
    return errors


def main():
    args = parse_args()

    if args.list:
        print("\nMigration Groups:")
        for key, g in GROUPS.items():
            print(f"  {g['emoji']}  {key:<15} — {g['description']}")
            print(f"              phases: {', '.join(g['phases'])}")
        print()
        return

    if args.source_shop:  CONFIG["source_shop"]  = args.source_shop
    if args.source_token: CONFIG["source_token"] = args.source_token
    if args.dest_shop:    CONFIG["dest_shop"]     = args.dest_shop
    if args.dest_token:   CONFIG["dest_token"]    = args.dest_token

    errs = validate_config(CONFIG)
    if errs:
        print("❌  Configuration errors:")
        for e in errs: print(e)
        print("\n  export SOURCE_SHOP=...  SOURCE_CLIENT_ID=...  SOURCE_CLIENT_SECRET=...")
        print("  export DEST_SHOP=...    DEST_CLIENT_ID=...    DEST_CLIENT_SECRET=...")
        sys.exit(1)

    log.info("")
    log.info("╔══════════════════════════════════════════════════════════╗")
    log.info("║      SHOPIFY STORE MIGRATION TOOL                       ║")
    log.info(f"║  {CONFIG['source_shop'][:20]:<20} → {CONFIG['dest_shop'][:20]:<20}  ║")
    log.info("╚══════════════════════════════════════════════════════════╝")
    log.info(f"  Source:      {CONFIG['source_shop']}")
    log.info(f"  Destination: {CONFIG['dest_shop']}")
    log.info(f"  API version: {CONFIG['api_version']}")
    log.info(f"  Dry run:     {args.dry_run}")
    log.info(f"  Resume:      {args.resume}")
    log.info(f"  Started:     {datetime.now(timezone.utc).isoformat()}Z")
    log.info("")

    src = ShopifyClient(shop=CONFIG["source_shop"],
                        token=CONFIG.get("source_token", ""),
                        api_version=CONFIG["api_version"], label="SOURCE",
                        client_id=CONFIG.get("source_client_id", ""),
                        client_secret=CONFIG.get("source_client_secret", ""))
    dst = ShopifyClient(shop=CONFIG["dest_shop"],
                        token=CONFIG.get("dest_token", ""),
                        api_version=CONFIG["api_version"], label="DEST",
                        client_id=CONFIG.get("dest_client_id", ""),
                        client_secret=CONFIG.get("dest_client_secret", ""))

    log.info("  Pre-flight connection tests ...")
    if not src.test_connection() or not dst.test_connection():
        log.error("\n❌  Connection failed — fix errors above and re-run.")
        sys.exit(1)
    log.info("  ✅  Both stores connected\n")

    if not args.resume and Path(CONFIG["state_file"]).exists():
        bk = CONFIG["state_file"] + f".backup_{int(time.time())}"
        Path(CONFIG["state_file"]).rename(bk)
        log.info(f"  Previous state backed up to {bk}")

    state    = MigrationState(CONFIG["state_file"])
    migrator = Migrator(src, dst, state, dry_run=args.dry_run)

    if args.validate:
        migrator.validate(); return
    if args.generate_redirects:
        migrator.generate_seo_redirects(); return

    # ── Determine selected groups / phases ────────────────────────────────
    if args.all:
        selected_groups = list(GROUPS.keys())
        log.info("  Running ALL groups")
    elif args.groups:
        selected_groups = args.groups
        log.info(f"  Groups: {', '.join(selected_groups)}")
    else:
        log.info("  Launching interactive group selector ...")
        for h in logging.root.handlers: h.flush()
        selected_groups = interactive_selector()

    phases = groups_to_phases(selected_groups)

    log.info("")
    log.info(f"  Selected groups : {', '.join(selected_groups)}")
    log.info(f"  Phases to run   : {', '.join(phases)}")
    log.info("")

    start = time.time()
    for phase in phases:
        try:
            getattr(migrator, PHASE_METHODS[phase])()
        except KeyboardInterrupt:
            log.info("\n⛔  Interrupted. Re-run with --resume to continue.")
            sys.exit(0)
        except Exception as exc:
            log.error(f"\n❌  Phase '{phase}' failed: {exc}")
            import traceback; log.error(traceback.format_exc())
            log.error("  State saved. Fix the error and re-run with --resume")
            sys.exit(1)

    elapsed = time.time() - start
    log.info("")
    log.info(f"✅  All phases complete in {elapsed / 60:.1f} minutes")
    migrator.generate_seo_redirects()
    migrator.validate()
    migrator.print_manual_steps()
    log.info("\n🎉  Migration complete!  Review migration.log for full details.")


if __name__ == "__main__":
    main()
