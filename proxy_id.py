# proxy_id.py — ambil 50 proxy Indonesia dari Proxifly
# deps: pip install requests
import random
import threading
import requests

SOURCE_ID   = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/ID/data.txt"
SOURCE_HTTP = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"
OUT_FILE    = "proxies.txt"
TARGET      = 50
TIMEOUT     = 6
TEST_URL    = "http://httpbin.org/ip"
UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36"

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

def check_proxy(proxy: str, results: list, lock: threading.Lock):
    try:
        r = requests.get(
            TEST_URL,
            proxies={"http": proxy, "https": proxy},
            timeout=TIMEOUT,
            headers={"User-Agent": UA},
        )
        if r.status_code == 200 and "origin" in r.text:
            with lock:
                results.append(proxy)
    except Exception:
        pass

def health_check(candidates: list, target: int) -> list:
    random.shuffle(candidates)
    results = []
    lock = threading.Lock()
    for i in range(0, len(candidates), 50):
        if len(results) >= target:
            break
        batch = candidates[i:i + 50]
        threads = []
        for p in batch:
            t = threading.Thread(target=check_proxy, args=(p, results, lock))
            t.daemon = True
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=TIMEOUT + 2)
    return results[:target]

def main():
    print("[~] ambil proxy Indonesia dari Proxifly...")
    id_raw = fetch_list(SOURCE_ID)
    print(f"[+] {len(id_raw)} proxy ID ditemukan")

    if not id_raw:
        print("[!] list ID kosong, fallback ke HTTP global...")
        id_raw = fetch_list(SOURCE_HTTP)[:500]
        print(f"[+] {len(id_raw)} kandidat global")

    candidates = list({normalize(p) for p in id_raw if p.startswith("http")})
    print(f"[~] health-check sampai dapat {TARGET} hidup...")
    alive = health_check(candidates, TARGET)
    print(f"[+] {len(alive)} proxy hidup")

    if alive:
        with open(OUT_FILE, "w") as f:
            for p in alive:
                f.write(p + "\n")
        print(f"[+] disimpan ke {OUT_FILE}")
        for p in alive[:5]:
            print("   ", p)
        if len(alive) > 5:
            print(f"    ... +{len(alive)-5} lagi")
    else:
        print("[!] nol proxy hidup—coba ulang beberapa menit lagi")

if __name__ == "__main__":
    main()
