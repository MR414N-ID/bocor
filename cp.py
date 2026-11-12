# proxy_id.py — scrape + filter proxy Indonesia yang aktif DAN lolos BPJS
# deps: pip install requests
# run: python proxy_id.py

import random
import threading
import requests

SOURCE_ID   = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/ID/data.txt"
SOURCE_HTTP = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"
OUT_FILE    = "proxies.txt"
TARGET      = 50
TIMEOUT     = 6
UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36"

TEST_ACTIVE = "https://httpbin.org/ip"
TEST_BPJS   = "https://pasti.bpjs-kesehatan.go.id/cek"

def fetch_list(url: str) -> list:
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": UA})
        if r.status_code == 200:
            return [l.strip() for l in r.text.splitlines() if l.strip() and ":" in l]
    except Exception:
        pass
    return []

def normalize(p: str) -> str:
    p = p.strip()
    if not p.startswith("http://") and not p.startswith("https://") and not p.startswith("socks"):
        return "http://" + p
    return p

def check_active(proxy: str) -> tuple:
    """return (ok, ip_or_err)"""
    try:
        r = requests.get(
            TEST_ACTIVE,
            proxies={"http": proxy, "https": proxy},
            timeout=TIMEOUT,
            headers={"User-Agent": UA},
        )
        if r.status_code == 200 and "origin" in r.text:
            return True, r.json().get("origin", "?")
        return False, f"http {r.status_code}"
    except requests.exceptions.ProxyError:
        return False, "proxy error"
    except requests.exceptions.ConnectTimeout:
        return False, "timeout"
    except requests.exceptions.ReadTimeout:
        return False, "read timeout"
    except Exception as e:
        return False, type(e).__name__

def check_bpjs(proxy: str) -> tuple:
    """return (ok, status_or_err)"""
    try:
        r = requests.get(
            TEST_BPJS,
            proxies={"http": proxy, "https": proxy},
            timeout=TIMEOUT + 2,
            headers={
                "User-Agent": UA,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            },
        )
        # BPJS suka balikin 403/503 kalau IP blacklist, 200 kalau lolos
        if r.status_code == 200:
            return True, "200"
        return False, f"http {r.status_code}"
    except requests.exceptions.ProxyError:
        return False, "proxy error"
    except requests.exceptions.ConnectTimeout:
        return False, "timeout"
    except requests.exceptions.ReadTimeout:
        return False, "read timeout"
    except Exception as e:
        return False, type(e).__name__

def worker(proxy: str, results: list, lock: threading.Lock):
    # step 1: aktif?
    ok_active, info_active = check_active(proxy)
    if not ok_active:
        with lock:
            results.append({"proxy": proxy, "ok": False, "stage": "aktif", "err": info_active, "ip": None})
        return

    # step 2: lolos BPJS?
    ok_bpjs, info_bpjs = check_bpjs(proxy)
    with lock:
        results.append({
            "proxy": proxy,
            "ok": ok_bpjs,
            "stage": "bpjs" if ok_bpjs else "bpjs-gagal",
            "err": None if ok_bpjs else info_bpjs,
            "ip": info_active,
        })

def run_batch(candidates: list, target: int) -> list:
    random.shuffle(candidates)
    results = []
    lock = threading.Lock()
    for i in range(0, len(candidates), 50):
        good = [r for r in results if r["ok"]]
        if len(good) >= target:
            break
        batch = candidates[i:i + 50]
        threads = []
        for p in batch:
            t = threading.Thread(target=worker, args=(p, results, lock))
            t.daemon = True
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=TIMEOUT * 2 + 4)
    return results

def main():
    print("[~] ambil proxy Indonesia dari Proxifly...")
    id_raw = fetch_list(SOURCE_ID)
    print(f"[+] {len(id_raw)} proxy ID ditemukan")

    if not id_raw:
        print("[!] list ID kosong, fallback ke HTTP global...")
        id_raw = fetch_list(SOURCE_HTTP)[:500]
        print(f"[+] {len(id_raw)} kandidat global")

    # filter hanya http:// (BPJS pakai http/https, bukan socks)
    candidates = list({normalize(p) for p in id_raw if p.startswith("http")})
    # buang duplikat & yang bukan format ip:port
    candidates = [c for c in candidates if c.count(":") >= 2]

    if not candidates:
        print("[!] tidak ada kandidat http")
        return

    print(f"[~] cek {len(candidates)} kandidat: aktif + lolos BPJS...\n")
    results = run_batch(candidates, TARGET)

    # urutkan: yang lolos BPJS di atas
    results.sort(key=lambda x: (not x["ok"], x["proxy"]))

    aktif = 0
    lolos = 0
    for r in results:
        if r["ok"]:
            lolos += 1
            print(f"  [✓] {r['proxy']:<42} exit: {r['ip']:<18} BPJS: lolos")
        elif r["stage"] == "bpjs-gagal":
            aktif += 1
            print(f"  [•] {r['proxy']:<42} exit: {r['ip']:<18} BPJS: {r['err']}")
        else:
            print(f"  [✗] {r['proxy']:<42} mati ({r['err']})")

    print(f"\n[+] ringkasan:")
    print(f"    aktif       : {aktif + lolos}/{len(results)}")
    print(f"    lolos BPJS  : {lolos}/{len(results)}")

    if lolos:
        with open(OUT_FILE, "w") as f:
            for r in results:
                if r["ok"]:
                    f.write(r["proxy"] + "\n")
        print(f"[+] {lolos} proxy lolos BPJS disimpan ke {OUT_FILE}")
    else:
        print("[!] nol proxy lolos BPJS—coba beberapa menit lagi")
        # fallback: simpan yang aktif aja biar tetap ada
        if aktif:
            with open(OUT_FILE, "w") as f:
                for r in results:
                    if r["stage"] == "bpjs-gagal":
                        f.write(r["proxy"] + "\n")
            print(f"[~] fallback: {aktif} proxy aktif (tanpa filter BPJS) disimpan")

if __name__ == "__main__":
    main()
