# proxy_id.py — scrape + filter proxy 5 negara, aktif DAN lolos BPJS
# deps: pip install requests
# run: python proxy_id.py

import os
import random
import threading
import requests

# 5 negara sekaligus
COUNTRIES = ["ID", "SG", "MY", "US", "GB"]
BASE_URL  = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/{}/data.txt"

TARGET      = 50
TIMEOUT     = 6
UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36"

TEST_ACTIVE = "https://httpbin.org/ip"
TEST_BPJS   = "https://pasti.bpjs-kesehatan.go.id/cek"

_checked = 0
_total = 0
_lock_counter = threading.Lock()

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

def get_available_filename(base_name="proxies.txt") -> str:
    if not os.path.exists(base_name):
        return base_name
    name, ext = os.path.splitext(base_name)
    counter = 2
    while True:
        new_name = f"{name}{counter}{ext}"
        if not os.path.exists(new_name):
            return new_name
        counter += 1

def check_active(proxy: str) -> tuple:
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
    global _checked
    ok_active, info_active = check_active(proxy)
    if not ok_active:
        with lock:
            _checked += 1
            print(f"  [{_checked:>4}/{_total}] [✗] {proxy:<40} mati ({info_active})")
            results.append({"proxy": proxy, "ok": False, "stage": "aktif", "err": info_active, "ip": None})
        return

    ok_bpjs, info_bpjs = check_bpjs(proxy)
    with lock:
        _checked += 1
        if ok_bpjs:
            print(f"  [{_checked:>4}/{_total}] [✓] {proxy:<40} exit: {info_active:<15} BPJS: lolos")
        else:
            print(f"  [{_checked:>4}/{_total}] [•] {proxy:<40} exit: {info_active:<15} BPJS: {info_bpjs}")
            
        results.append({
            "proxy": proxy,
            "ok": ok_bpjs,
            "stage": "bpjs" if ok_bpjs else "bpjs-gagal",
            "err": None if ok_bpjs else info_bpjs,
            "ip": info_active,
        })

def run_batch(candidates: list, target: int) -> list:
    global _total
    random.shuffle(candidates)
    _total = len(candidates)
    
    results = []
    lock = threading.Lock()
    
    for i in range(0, len(candidates), 50):
        good = [r for r in results if r["ok"]]
        if len(good) >= target:
            print(f"\n[!] Target {target} proxy lolos tercapai, menghentikan sisa pencarian.")
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
    print(f"[~] ambil proxy dari {len(COUNTRIES)} negara ({', '.join(COUNTRIES)})...")
    
    raw_proxies = []
    for cc in COUNTRIES:
        url = BASE_URL.format(cc)
        print(f"    - Fetching {cc}...", end="", flush=True)
        data = fetch_list(url)
        print(f" dapat {len(data)}")
        raw_proxies.extend(data)

    print(f"\n[+] Total {len(raw_proxies)} proxy terkumpul dari semua negara")

    candidates = list({normalize(p) for p in raw_proxies if p.startswith("http")})
    candidates = [c for c in candidates if c.count(":") >= 2]

    if not candidates:
        print("[!] Tidak ada kandidat yang valid.")
        return

    print(f"[~] Mulai cek {len(candidates)} kandidat (aktif + lolos BPJS)...\n")
    results = run_batch(candidates, TARGET)

    berhasil = [r for r in results if r["ok"]]
    aktif_gagal_bpjs = [r for r in results if r["stage"] == "bpjs-gagal"]
    
    print("\n" + "-" * 50)
    print(f"LIST YANG BERHASIL LOLOS BPJS ({len(berhasil)} Proxy)")
    print("-" * 50)
    
    if berhasil:
        for r in berhasil:
            print(f"  {r['proxy']}")
    else:
        print("  Tidak ada proxy yang lolos BPJS.")

    # Konfirmasi Save
    if berhasil:
        print() 
        pilihan = input("[?] Simpan proxy ini ke file? (y/t): ").strip().lower()
        
        if pilihan == 'y':
            target_file = get_available_filename("proxies.txt")
            with open(target_file, "w") as f:
                for r in berhasil:
                    f.write(r["proxy"] + "\n")
            print(f"[+] Berhasil disimpan ke {target_file}")
        else:
            print("[-] Dibatalkan, proxy tidak disimpan.")
        
    print(f"\n[+] Ringkasan:")
    print(f"    - Total dicek      : {_checked}")
    print(f"    - Mati             : {len(results) - len(berhasil) - len(aktif_gagal_bpjs)}")
    print(f"    - Aktif (Gagal BPJS): {len(aktif_gagal_bpjs)}")
    print(f"    - Lolos BPJS       : {len(berhasil)}")

if __name__ == "__main__":
    main()
