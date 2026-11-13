"""VRAM Guard AMD — protection contre les zones defectueuses de memoire video (cartes AMD Radeon, Windows).

Version AMD de VRAM Guard. Meme principe que la version NVIDIA : la VRAM libre est testee par
blocs de 64 Mo (4 motifs dependants de l'adresse). Les blocs qui renvoient des erreurs sont
gardes alloues par ce programme : aucun autre programme ne peut plus les recevoir. Les bons
blocs sont liberes. Un bloc defectueux n'est jamais rendu. Quand la carte est presque libre
(>= 75 %), un nouveau test complet est fait au plus toutes les 30 minutes (plafond : 1 Gio
garde par carte).

Differences techniques avec la version NVIDIA :
  - CUDA/PTX      -> OpenCL (OpenCL.dll, fourni par le pilote AMD), noyaux en OpenCL C ;
  - NVML          -> DXGI (liste des cartes, taille de la VRAM) + compteurs de performance
                     Windows "GPU Adapter Memory" (VRAM utilisee par tous les programmes) ;
  - les puces graphiques integrees (memoire partagee avec la RAM) sont ignorees.

Modes :
  VRAM-Guard-AMD.exe                -> fenetre (etat, installation, test)
  VRAM-Guard-AMD.exe --background   -> protection en arriere-plan (lancee au demarrage)
  VRAM-Guard-AMD.exe --test         -> test seul, resultat dans le journal, puis sortie

Limites : cartes AMD dediees uniquement. Ne repare pas la carte. Ne protege que la VRAM libre
au moment du test. Si la carte est pleine (jeu tres gourmand), Windows peut deplacer la memoire
gardee : le programme la recapture des que la carte se libere.
"""
import ctypes
import datetime
import os
import subprocess
import sys
import threading
import time
from ctypes import byref, c_int, c_size_t, c_uint, c_uint32, c_uint64, c_void_p

APP = "VRAM Guard AMD"
VERSION = "1.0"
EXE_NAME = "VRAM-Guard-AMD.exe"
DATA = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "VRAM-Guard-AMD")
os.makedirs(DATA, exist_ok=True)
LOG = os.path.join(DATA, "vram-guard.log")
STATUS = os.path.join(DATA, "etat.txt")
INSTALLED_EXE = os.path.join(DATA, EXE_NAME)
STARTUP_LNK = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup",
                           "VRAM Guard AMD.lnk")
MUTEX = "Local\\VramGuardAmdBackground"
CHUNK = 64 * 1024 * 1024
MARGIN = 400 * 1024 * 1024
SEEDS = (0x00000000, 0xFFFFFFFF, 0xA5A5A5A5, 0x5A5A5A5A)
CHECK_EVERY = 300
AMD_VENDOR = 0x1002

# Memes motifs que la version NVIDIA : mot i = (i * 2654435761) xor graine.
KERNELS = rb"""
__kernel void fill(__global uint *p, uint seed)
{
    uint i = (uint)get_global_id(0);
    p[i] = (i * 2654435761u) ^ seed;
}

__kernel void check(__global const uint *p, uint seed, __global volatile uint *cnt)
{
    uint i = (uint)get_global_id(0);
    if (p[i] != ((i * 2654435761u) ^ seed))
        atomic_inc(cnt);
}
"""


# ----------------------------------------------------------------------------- journal
def log(msg):
    line = f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} {msg}"
    try:
        if os.path.exists(LOG) and os.path.getsize(LOG) > 300_000:
            with open(LOG, encoding="utf-8") as f:
                keep = f.readlines()[-400:]
            with open(LOG, "w", encoding="utf-8") as f:
                f.writelines(keep)
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ----------------------------------------------------------------------------- DXGI + compteurs Windows
class _Luid(ctypes.Structure):
    _fields_ = [("low", c_uint32), ("high", ctypes.c_int32)]


class _DxgiDesc(ctypes.Structure):
    _fields_ = [("description", ctypes.c_wchar * 128), ("vendor", c_uint), ("device", c_uint),
                ("subsys", c_uint), ("revision", c_uint), ("dedicated_video", c_size_t),
                ("dedicated_system", c_size_t), ("shared_system", c_size_t), ("luid", _Luid)]


class _Guid(ctypes.Structure):
    _fields_ = [("d1", c_uint32), ("d2", ctypes.c_uint16), ("d3", ctypes.c_uint16), ("d4", ctypes.c_ubyte * 8)]


def _com(obj, index, restype, *argtypes):
    """Methode numero `index` de la table virtuelle d'un objet COM."""
    vtbl = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(c_void_p))).contents
    return ctypes.WINFUNCTYPE(restype, c_void_p, *argtypes)(vtbl[index])


def dxgi_adapters():
    """Cartes AMD vues par Windows : [{name, total, luid}] (liste vide si DXGI indisponible)."""
    out = []
    try:
        dxgi = ctypes.WinDLL("dxgi.dll")
        iid = _Guid(0x7b7166ec, 0x21c7, 0x44ae, (ctypes.c_ubyte * 8)(0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69))
        factory = c_void_p()
        if dxgi.CreateDXGIFactory(byref(iid), byref(factory)) != 0:
            return out
        i = 0
        while True:
            adapter = c_void_p()
            if _com(factory, 7, c_int, c_uint, ctypes.POINTER(c_void_p))(factory, i, byref(adapter)) != 0:
                break
            desc = _DxgiDesc()
            if _com(adapter, 8, c_int, ctypes.POINTER(_DxgiDesc))(adapter, byref(desc)) == 0 \
                    and desc.vendor == AMD_VENDOR:
                out.append({"name": desc.description, "total": desc.dedicated_video,
                            "luid": f"luid_0x{desc.luid.high & 0xFFFFFFFF:08X}_0x{desc.luid.low:08X}"})
            _com(adapter, 2, c_uint)(adapter)
            i += 1
        _com(factory, 2, c_uint)(factory)
    except OSError:
        pass
    return out


class _PdhValue(ctypes.Structure):
    _fields_ = [("status", c_uint32), ("value", ctypes.c_longlong)]


class DedicatedUsage:
    """VRAM dediee utilisee sur une carte (compteur de performance Windows) : par TOUS les
    programmes, ou par un seul si `pid` est donne."""

    def __init__(self, luid, pid=None):
        self.pdh = ctypes.WinDLL("pdh.dll")
        self.query, self.counter = c_void_p(), c_void_p()
        path = (f"\\GPU Process Memory(pid_{pid}_{luid}_phys_0)\\Dedicated Usage" if pid
                else f"\\GPU Adapter Memory({luid}_phys_0)\\Dedicated Usage")
        self.ok = (self.pdh.PdhOpenQueryW(None, c_void_p(0), byref(self.query)) == 0
                   and self.pdh.PdhAddEnglishCounterW(self.query, ctypes.c_wchar_p(path), c_void_p(0),
                                                      byref(self.counter)) == 0)

    def read(self):
        if not self.ok:
            return None
        val = _PdhValue()
        if self.pdh.PdhCollectQueryData(self.query) != 0:
            return None
        if self.pdh.PdhGetFormattedCounterValue(self.counter, c_uint(0x400), None, byref(val)) != 0:
            return None
        return val.value


# ----------------------------------------------------------------------------- OpenCL
class ClError(RuntimeError):
    def __init__(self, name, code):
        super().__init__(f"{name} -> erreur OpenCL {code}")
        self.code = code


class Cl:
    def __init__(self):
        self.cl = ctypes.WinDLL("OpenCL.dll")
        for n in ("clCreateContext", "clCreateCommandQueue", "clCreateProgramWithSource", "clCreateKernel",
                  "clCreateBuffer"):
            getattr(self.cl, n).restype = c_void_p

    def __call__(self, name, *args):
        r = getattr(self.cl, name)(*args)
        if r != 0:
            raise ClError(name, r)

    def create(self, name, *args):
        err = c_int()
        h = getattr(self.cl, name)(*args, byref(err))
        if err.value != 0 or not h:
            raise ClError(name, err.value)
        return c_void_p(h)

    def info(self, dev, param):
        size = c_size_t()
        self("clGetDeviceInfo", dev, c_uint(param), c_size_t(0), None, byref(size))
        buf = ctypes.create_string_buffer(size.value)
        self("clGetDeviceInfo", dev, c_uint(param), size, buf, None)
        return buf.raw

    def text(self, dev, param):
        try:
            return self.info(dev, param).split(b"\0")[0].decode(errors="replace").strip()
        except ClError:
            return ""

    def amd_gpus(self):
        """Cartes AMD dediees vues par OpenCL : [(device, nom, memoire)]."""
        n = c_uint()
        self("clGetPlatformIDs", c_uint(0), None, byref(n))
        plats = (c_void_p * n.value)()
        self("clGetPlatformIDs", n, plats, None)
        found, seen = [], set()
        for p in plats:
            nd = c_uint()
            try:
                self("clGetDeviceIDs", c_void_p(p), c_uint64(4), c_uint(0), None, byref(nd))   # 4 = GPU
                devs = (c_void_p * nd.value)()
                self("clGetDeviceIDs", c_void_p(p), c_uint64(4), nd, devs, None)
            except ClError:
                continue
            for d in devs:
                d = c_void_p(d)
                vendor = int.from_bytes(self.info(d, 0x1001)[:4], "little")
                unified = int.from_bytes(self.info(d, 0x1035)[:4], "little")      # puce integree
                if vendor != AMD_VENDOR or unified:
                    continue
                try:                                      # meme emplacement PCI = meme carte vue par deux pilotes
                    slot = self.info(d, 0x4037)
                    if slot in seen:
                        continue
                    seen.add(slot)
                except ClError:
                    pass
                name = self.text(d, 0x4038) or self.text(d, 0x102B)               # nom commercial AMD, sinon nom
                mem = int.from_bytes(self.info(d, 0x101F)[:8], "little")
                found.append((d, name, mem))
        return found


def _norm(s):
    return " ".join(s.lower().replace("(tm)", "").replace("(r)", "").split())


def find_cards(cl):
    """Associe chaque carte OpenCL a sa carte Windows (DXGI). Retourne [(device, nom, total, luid|None)]."""
    # Une meme carte peut apparaitre deux fois dans DXGI (ecran virtuel, emulateur...) : seule la
    # vraie a un compteur de memoire Windows.
    adapters = [a for a in dxgi_adapters() if DedicatedUsage(a["luid"]).read() is not None]
    has_dxgi = bool(adapters)
    cards = []
    for dev, name, mem in cl.amd_gpus():
        match = None
        if has_dxgi:
            same = [a for a in adapters if _norm(a["name"]) == _norm(name)]
            pool = same or [a for a in adapters if a["total"] > 2**30]
            if not pool:
                continue                                  # deja prise (meme carte vue par deux pilotes OpenCL)
            match = min(pool, key=lambda a: abs(a["total"] - mem))
            adapters.remove(match)
        cards.append((dev, match["name"] if match else name, match["total"] if match else mem,
                      match["luid"] if match else None))
    return cards


class GpuGuard:
    """Test et garde des blocs defectueux d'une carte."""

    def __init__(self, cl, index, dev, name, total, luid):
        self.cl, self.index, self.name, self.total = cl, index, " ".join(name.split()), total
        self.usage = DedicatedUsage(luid) if luid else None
        self.luid, self.mine = luid, None
        devs = (c_void_p * 1)(dev)
        self.ctx = cl.create("clCreateContext", None, c_uint(1), devs, None, None)
        self.queue = cl.create("clCreateCommandQueue", self.ctx, dev, c_uint64(0))
        src = ctypes.c_char_p(KERNELS)
        prog = cl.create("clCreateProgramWithSource", self.ctx, c_uint(1), byref(src), None)
        try:
            cl("clBuildProgram", prog, c_uint(1), devs, None, None, None)
        except ClError as e:
            buf = ctypes.create_string_buffer(8192)
            cl.cl.clGetProgramBuildInfo(prog, dev, c_uint(0x1183), c_size_t(8192), buf, None)
            raise RuntimeError(f"compilation OpenCL impossible ({e}) : {buf.value.decode(errors='replace')}")
        self.k_fill = cl.create("clCreateKernel", prog, b"fill")
        self.k_check = cl.create("clCreateKernel", prog, b"check")
        self.n_words = CHUNK // 4
        self.cnt = self._alloc(4)
        self.kept = []
        self.self_test()

    def _alloc(self, size):
        return self.cl.create("clCreateBuffer", self.ctx, c_uint64(1), c_size_t(size), None)   # 1 = lecture/ecriture

    def _free(self, buf):
        self.cl("clReleaseMemObject", buf)

    def _run(self, kernel):
        n = c_size_t(self.n_words)
        self.cl("clEnqueueNDRangeKernel", self.queue, kernel, c_uint(1), None, byref(n), None, c_uint(0), None, None)

    def _sync(self):
        self.cl("clFinish", self.queue)

    def _fill(self, buf, seed):
        self.cl("clSetKernelArg", self.k_fill, c_uint(0), c_size_t(8), byref(buf))
        self.cl("clSetKernelArg", self.k_fill, c_uint(1), c_size_t(4), byref(c_uint32(seed & 0xFFFFFFFF)))
        self._run(self.k_fill)

    def _errors(self, buf, seed):
        host = c_uint32(0)
        self.cl("clEnqueueWriteBuffer", self.queue, self.cnt, c_uint(1), c_size_t(0), c_size_t(4), byref(host),
                c_uint(0), None, None)
        self.cl("clSetKernelArg", self.k_check, c_uint(0), c_size_t(8), byref(buf))
        self.cl("clSetKernelArg", self.k_check, c_uint(1), c_size_t(4), byref(c_uint32(seed & 0xFFFFFFFF)))
        self.cl("clSetKernelArg", self.k_check, c_uint(2), c_size_t(8), byref(self.cnt))
        self._run(self.k_check)
        self.cl("clEnqueueReadBuffer", self.queue, self.cnt, c_uint(1), c_size_t(0), c_size_t(4), byref(host),
                c_uint(0), None, None)
        return host.value

    def _corrupt(self, buf):
        """Essai uniquement (VRAM_GUARD_SIMULATE) : abime un mot du bloc pour verifier la detection."""
        junk = c_uint32(0xDEADBEEF)
        self.cl("clEnqueueWriteBuffer", self.queue, buf, c_uint(1), c_size_t(4096), c_size_t(4), byref(junk),
                c_uint(0), None, None)

    def free_vram(self):
        """VRAM reellement libre (tous programmes confondus), ou None si Windows ne la donne pas."""
        used = self.usage.read() if self.usage else None
        return None if used is None else max(0, self.total - used)

    def own_vram(self):
        """VRAM dediee tenue par ce programme seul (insensible aux autres programmes), ou None."""
        if self.luid and not (self.mine and self.mine.ok):
            self.mine = DedicatedUsage(self.luid, os.getpid())
        return self.mine.read() if self.mine else None

    def self_test(self):
        """Le testeur doit detecter un mauvais motif partout, sinon on ne lui fait pas confiance."""
        p = self._alloc(CHUNK)
        self._fill(p, 1234)
        self._sync()
        diff = self._errors(p, 4321)
        self._free(p)
        if diff != self.n_words:
            raise RuntimeError(f"auto-test du testeur en echec sur {self.name} ({diff}/{self.n_words})")

    def scan(self, keep=True):
        """Teste la VRAM reellement libre. Retourne (blocs defectueux trouves, Mio testes)."""
        free = self.free_vram()
        if free is None:
            log(f"[GPU {self.index} {self.name}] VRAM libre inconnue (compteur Windows indisponible) : "
                f"test limite a la moitie de la carte")
            free = self.total // 2 + MARGIN
        used0 = self.own_vram()
        target = max(0, (free - MARGIN) // CHUNK)
        t0 = time.time()
        chunks = []
        # OpenCL n'alloue vraiment qu'a la premiere ecriture : chaque bloc est rempli tout de suite.
        # On s'arrete avant de remplir la carte, sinon Windows deborderait dans la RAM partagee.
        while len(chunks) < target:
            batch = []
            try:
                for _ in range(min(4, target - len(chunks))):
                    batch.append(self._alloc(CHUNK))
                    self._fill(batch[-1], 0)
                self._sync()
            except ClError:
                for p in batch:
                    try:
                        self._free(p)
                    except ClError:
                        pass
                break
            chunks += batch
            left = self.free_vram()
            if left is not None and left < MARGIN // 2:
                break
        t_alloc = time.time()
        simulate = {int(x) for x in os.environ.get("VRAM_GUARD_SIMULATE", "").split(",") if x.strip().isdigit()}
        bad = {}
        for seed in SEEDS:
            for i, p in enumerate(chunks):
                self._fill(p, seed ^ (i * 7919))
            self._sync()
            for i in simulate:
                if i < len(chunks):
                    self._corrupt(chunks[i])
            for i, p in enumerate(chunks):
                e = self._errors(p, seed ^ (i * 7919))
                if e:
                    bad[i] = bad.get(i, 0) + e
        time.sleep(max(0.0, 1.5 - (time.time() - t_alloc)))   # le compteur Windows a ~1 s de retard
        used1 = self.own_vram()
        for i, p in enumerate(chunks):
            if keep and i in bad:
                self.kept.append(p)
            else:
                self._free(p)
        self._sync()
        detail = ", ".join(f"bloc {i}: {n} erreurs" for i, n in sorted(bad.items())) or "aucun"
        where = ""
        if used0 is not None and used1 is not None and chunks:
            in_vram = max(0, used1 - used0)
            where = f" ({in_vram / 2**20:.0f} Mio places en VRAM dediee)"
            if in_vram < 0.8 * len(chunks) * CHUNK:
                where += " ATTENTION : une partie du test n'etait pas en VRAM dediee"
        if keep:
            time.sleep(1.5)                               # le compteur Windows a ~1 s de retard
            held = self.own_vram()
            if held is not None:
                where += f" ; VRAM tenue par VRAM Guard apres liberation : {held / 2**20:.0f} Mio"
        log(f"[GPU {self.index} {self.name}] {self.total / 2**30:.1f} Gio, test de {len(chunks) * 64} Mio{where} "
            f"en {time.time() - t0:.0f} s : {len(bad)} bloc(s) defectueux [{detail}]"
            + (f" ; total garde {len(self.kept) * 64} Mio" if keep else " (test seul, rien n'est garde)"))
        return len(bad), len(chunks) * 64

    def periodic(self):
        """Un bloc defectueux n'est jamais libere (certains defauts sont des effets d'alias :
        teste seul, le bloc parait sain). Nouveau test complet quand la carte est presque
        libre (>= 75 %), au plus toutes les 30 min, pour rattraper une zone que Windows aurait
        liberee en deplacant de la memoire. Plafond : 16 blocs (1 Gio) par carte."""
        idle = (self.free_vram() or 0) + len(self.kept) * CHUNK >= 0.75 * self.total
        if idle and len(self.kept) < 16 and time.time() - getattr(self, "last_scan", 0) >= 1800:
            self.scan()
            self.last_scan = time.time()


def init_guards():
    for _ in range(20):          # le pilote peut ne pas etre pret juste apres l'ouverture de session
        try:
            cl = Cl()
            cards = find_cards(cl)
            if cards:
                break
            reason = "aucune carte AMD dediee trouvee"
        except (OSError, ClError) as e:
            reason = str(e)
        log(f"pilote AMD pas pret ({reason}), nouvel essai dans 15 s")
        if "--background" not in sys.argv:
            raise RuntimeError(f"aucune carte AMD dediee utilisable ({reason})")
        time.sleep(15)
    else:
        raise RuntimeError("pilote AMD (OpenCL) indisponible")
    return [GpuGuard(cl, i, *card) for i, card in enumerate(cards)]


def write_status(guards):
    parts = [f"GPU {g.index} {g.name} : {len(g.kept)} bloc(s) defectueux garde(s) ({len(g.kept) * 64} Mio)"
             for g in guards] or ["aucun bloc defectueux trouve : aucune VRAM n'est gardee"]
    with open(STATUS, "w", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} protection active\n" + "\n".join(parts) + "\n")


def child_scan():
    """Test seul dans un processus separe. 0 = aucune erreur, 10 = blocs defectueux, autre = echec.
    Le pilote AMD garde en cache une partie de la VRAM liberee tant que le processus vit :
    tester dans un processus qui se termine rend toute la VRAM quand la carte est saine."""
    cmd = ([sys.executable] if frozen() else [sys.executable, exe_path()]) + ["--scan-child"]
    try:
        return subprocess.run(cmd, creationflags=0x08000000, timeout=1800).returncode
    except Exception:  # noqa: BLE001
        return -1


def cards_idle():
    """Vrai si une carte AMD dediee est presque libre (>= 75 %), sans ouvrir OpenCL."""
    for a in dxgi_adapters():
        used = DedicatedUsage(a["luid"]).read()
        if used is not None and a["total"] > 2**30 and a["total"] - used >= 0.75 * a["total"]:
            return True
    return False


def run_background():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.restype = c_void_p
    _m = k32.CreateMutexW(None, False, MUTEX)
    if ctypes.get_last_error() == 183:
        return
    try:
        guards = []

        def take_over():
            """Des blocs defectueux existent : ce processus les teste lui-meme et les garde."""
            guards.extend(init_guards())
            for g in guards:
                g.scan()
                g.last_scan = time.time()

        if child_scan() != 0:
            take_over()
        last_child = time.time()
        write_status(guards)
        k32.GetCurrentProcess.restype = c_void_p
        k32.SetPriorityClass(c_void_p(k32.GetCurrentProcess()), 0x40)   # priorite basse
        while True:
            time.sleep(CHECK_EVERY)
            if not guards:
                if time.time() - last_child >= 1800 and cards_idle():
                    last_child = time.time()
                    if child_scan() == 10:
                        take_over()
            for g in guards:
                try:
                    g.periodic()
                except ClError as e:
                    log(f"[GPU {g.index}] verification impossible ({e}), nouvel essai plus tard")
            write_status(guards)
    except Exception as e:  # noqa: BLE001
        log(f"ERREUR : {e!r}")
        try:
            with open(STATUS, "w", encoding="utf-8") as f:
                f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} ARRETE sur erreur : {e}\n")
        except OSError:
            pass


def run_test_only():
    results = []
    for g in init_guards():
        bad, tested = g.scan(keep=False)
        results.append((g.name, bad, tested))
    return results


# ----------------------------------------------------------------------------- installation
def frozen():
    return bool(getattr(sys, "frozen", False))


def exe_path():
    return sys.executable if frozen() else os.path.abspath(__file__)


def background_pids():
    """PID des instances --background (via PowerShell, sans dependance)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*--background*' -and "
             f"($_.Name -eq '{EXE_NAME}' -or $_.CommandLine -like '*vram_guard_amd_app.py*') }} | "
             "ForEach-Object { $_.ProcessId }"],
            capture_output=True, text=True, creationflags=0x08000000, timeout=20).stdout
        return [int(x) for x in out.split() if x.strip().isdigit()]
    except Exception:  # noqa: BLE001
        return []


def stop_background():
    for pid in background_pids():
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, creationflags=0x08000000)
    time.sleep(1)


def start_background():
    if os.path.exists(INSTALLED_EXE):
        cmd = [INSTALLED_EXE, "--background"]
    elif frozen():
        cmd = [exe_path(), "--background"]
    else:
        cmd = [sys.executable, exe_path(), "--background"]
    subprocess.Popen(cmd, creationflags=0x00000008 | 0x08000000, close_fds=True)


def install():
    if not frozen():
        raise RuntimeError("L'installation demande l'executable compile (voir README, « Compiler soi-meme »).")
    stop_background()
    src = exe_path()
    if os.path.abspath(src).lower() != os.path.abspath(INSTALLED_EXE).lower():
        import shutil
        shutil.copy2(src, INSTALLED_EXE)
    ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{STARTUP_LNK}');"
          f"$s.TargetPath='{INSTALLED_EXE}';$s.Arguments='--background';$s.WorkingDirectory='{DATA}';"
          f"$s.Description='VRAM Guard AMD : protection des zones defectueuses de la VRAM';$s.Save()")
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, creationflags=0x08000000)
    start_background()
    log("installe (lancement automatique a l'ouverture de session) et demarre")


def uninstall():
    stop_background()
    try:
        os.remove(STARTUP_LNK)
    except OSError:
        pass
    log("desinstalle (plus de lancement automatique)")


def is_installed():
    return os.path.exists(STARTUP_LNK)


# ----------------------------------------------------------------------------- fenetre
def run_gui():
    import tkinter as tk
    from tkinter import messagebox, scrolledtext

    root = tk.Tk()
    root.title(f"{APP} {VERSION}")
    root.geometry("640x470")
    root.minsize(560, 420)

    tk.Label(root, text=APP, font=("Segoe UI", 16, "bold")).pack(pady=(12, 0))
    tk.Label(root, text="Protege votre carte AMD Radeon contre ses zones de memoire video defectueuses\n"
                        "(artefacts, plantages de jeux, IA locale qui ecrit n'importe quoi).",
             font=("Segoe UI", 9), justify="center").pack(pady=(2, 8))

    state = tk.StringVar()
    tk.Label(root, textvariable=state, font=("Segoe UI", 10), justify="left", anchor="w",
             relief="groove", padx=10, pady=8).pack(fill="x", padx=14)

    bar = tk.Frame(root)
    bar.pack(pady=10)
    logbox = scrolledtext.ScrolledText(root, height=12, font=("Consolas", 9))
    logbox.pack(fill="both", expand=True, padx=14, pady=(0, 12))

    def refresh():
        running = bool(background_pids())
        inst = is_installed()
        status = ""
        try:
            with open(STATUS, encoding="utf-8") as f:
                status = f.read().strip()
        except OSError:
            status = "aucun test encore effectue"
        state.set(f"Protection en arriere-plan : {'ACTIVE' if running else 'arretee'}\n"
                  f"Lancement automatique au demarrage : {'oui' if inst else 'non'}\n{status}")
        try:
            with open(LOG, encoding="utf-8") as f:
                txt = "".join(f.readlines()[-60:])
        except OSError:
            txt = ""
        logbox.delete("1.0", "end")
        logbox.insert("end", txt)
        logbox.see("end")
        btn_install.config(text="Desinstaller" if inst else "Installer (protection permanente)")

    def busy(fn, msg):
        def work():
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                err = str(e)
                root.after(0, lambda: messagebox.showerror(APP, err))
            root.after(0, refresh)
        state.set(msg)
        threading.Thread(target=work, daemon=True).start()

    def on_install():
        if is_installed():
            if messagebox.askyesno(APP, "Arreter la protection et ne plus la lancer au demarrage ?"):
                busy(uninstall, "Desinstallation...")
        else:
            busy(install, "Installation et premier test de la VRAM...")
            root.after(4000, refresh)

    def on_test():
        if background_pids():
            if not messagebox.askyesno(APP, "La protection tourne deja. La relancer pour refaire un test complet ?"):
                return
            def restart():
                stop_background()
                start_background()
                time.sleep(6)
            busy(restart, "Nouveau test en cours...")
            return

        def test():
            res = run_test_only()
            lines = [f"{name} : {bad} bloc(s) de 64 Mo defectueux sur {tested} Mio testes" for name, bad, tested in res]
            any_bad = any(b for _, b, _ in res)
            msg = "\n".join(lines) + ("\n\nDes zones defectueuses existent : cliquez sur Installer pour les bloquer "
                                      "en permanence." if any_bad else "\n\nAucune erreur detectee dans la VRAM libre.")
            root.after(0, lambda: messagebox.showinfo(APP, msg))
        busy(test, "Test de la VRAM en cours (fermez les jeux pour tester toute la carte)...")

    def on_log():
        os.startfile(DATA)

    btn_install = tk.Button(bar, width=30, command=on_install)
    btn_install.grid(row=0, column=0, padx=4)
    tk.Button(bar, text="Tester maintenant", width=18, command=on_test).grid(row=0, column=1, padx=4)
    tk.Button(bar, text="Dossier du journal", width=16, command=on_log).grid(row=0, column=2, padx=4)

    def tick():
        refresh()
        root.after(10000, tick)
    tick()
    root.mainloop()


if __name__ == "__main__":
    if "--background" in sys.argv:
        run_background()
    elif "--scan-child" in sys.argv:
        try:
            sys.exit(10 if any(bad for _, bad, _ in run_test_only()) else 0)
        except Exception as e:  # noqa: BLE001
            log(f"ERREUR test : {e!r}")
            sys.exit(1)
    elif "--test" in sys.argv:
        try:
            for name, bad, tested in run_test_only():
                print(f"{name}: {bad} bloc(s) defectueux sur {tested} Mio")
        except Exception as e:  # noqa: BLE001
            log(f"ERREUR test : {e!r}")
            print(f"ERREUR test : {e}", file=sys.stderr)
            sys.exit(1)
    else:
        run_gui()
