"""VRAM Guard — protection contre les zones defectueuses de memoire video (cartes NVIDIA, Windows).

Principe : la VRAM libre est testee par blocs de 64 Mo (4 motifs dependants de l'adresse).
Les blocs qui renvoient des erreurs sont gardes alloues par ce programme : aucun autre
programme (jeu, IA locale, navigateur...) ne peut plus les recevoir. Les bons blocs sont
liberes. Un bloc defectueux n'est jamais rendu. Quand la carte est presque libre (>= 75 %),
un nouveau test complet est fait au plus toutes les 30 minutes pour rattraper une zone que
Windows aurait liberee en deplacant de la memoire (plafond : 1 Gio garde par carte).

Modes :
  VRAM-Guard.exe                -> fenetre (etat, installation, test)
  VRAM-Guard.exe --background   -> protection en arriere-plan (lancee au demarrage)
  VRAM-Guard.exe --test         -> test seul, resultat dans le journal, puis sortie

Limites : cartes NVIDIA uniquement (pilote recent). Ne repare pas la carte. Ne protege que la
VRAM libre au moment du test. Si la carte est pleine (jeu tres gourmand), Windows peut deplacer
la memoire gardee : le programme la recapture des que la carte se libere.
"""
import ctypes
import datetime
import os
import subprocess
import sys
import threading
import time
from ctypes import byref, c_int, c_size_t, c_uint, c_uint32, c_uint64, c_void_p

APP = "VRAM Guard"
VERSION = "1.0"
DATA = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "VRAM-Guard")
os.makedirs(DATA, exist_ok=True)
LOG = os.path.join(DATA, "vram-guard.log")
STATUS = os.path.join(DATA, "etat.txt")
INSTALLED_EXE = os.path.join(DATA, "VRAM-Guard.exe")
STARTUP_LNK = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup",
                           "VRAM Guard.lnk")
MUTEX = "Local\\VramGuardBackground"
CHUNK = 64 * 1024 * 1024
MARGIN = 400 * 1024 * 1024
SEEDS = (0x00000000, 0xFFFFFFFF, 0xA5A5A5A5, 0x5A5A5A5A)
CHECK_EVERY = 300
os.environ.setdefault("CUDA_DEVICE_ORDER", "PCI_BUS_ID")   # meme ordre que NVML

PTX = rb"""
.version 6.0
.target sm_50
.address_size 64

.visible .entry fill(.param .u64 p_ptr, .param .u32 p_seed, .param .u32 p_n)
{
    .reg .pred %p<2>;
    .reg .b32 %r<8>;
    .reg .b64 %rd<4>;
    ld.param.u64 %rd1, [p_ptr];
    ld.param.u32 %r1, [p_seed];
    ld.param.u32 %r2, [p_n];
    mov.u32 %r3, %ctaid.x;
    mov.u32 %r4, %ntid.x;
    mov.u32 %r5, %tid.x;
    mad.lo.u32 %r6, %r3, %r4, %r5;
    setp.ge.u32 %p1, %r6, %r2;
    @%p1 bra FILL_DONE;
    mul.lo.u32 %r7, %r6, -1640531535;
    xor.b32 %r7, %r7, %r1;
    cvta.to.global.u64 %rd2, %rd1;
    mul.wide.u32 %rd3, %r6, 4;
    add.u64 %rd2, %rd2, %rd3;
    st.global.u32 [%rd2], %r7;
FILL_DONE:
    ret;
}

.visible .entry check(.param .u64 p_ptr, .param .u32 p_seed, .param .u32 p_n, .param .u64 p_cnt)
{
    .reg .pred %p<3>;
    .reg .b32 %r<9>;
    .reg .b64 %rd<6>;
    ld.param.u64 %rd1, [p_ptr];
    ld.param.u32 %r1, [p_seed];
    ld.param.u32 %r2, [p_n];
    ld.param.u64 %rd4, [p_cnt];
    mov.u32 %r3, %ctaid.x;
    mov.u32 %r4, %ntid.x;
    mov.u32 %r5, %tid.x;
    mad.lo.u32 %r6, %r3, %r4, %r5;
    setp.ge.u32 %p1, %r6, %r2;
    @%p1 bra CHECK_DONE;
    mul.lo.u32 %r7, %r6, -1640531535;
    xor.b32 %r7, %r7, %r1;
    cvta.to.global.u64 %rd2, %rd1;
    mul.wide.u32 %rd3, %r6, 4;
    add.u64 %rd2, %rd2, %rd3;
    ld.global.cv.u32 %r8, [%rd2];
    setp.eq.u32 %p2, %r8, %r7;
    @%p2 bra CHECK_DONE;
    cvta.to.global.u64 %rd5, %rd4;
    red.global.add.u32 [%rd5], 1;
CHECK_DONE:
    ret;
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


# ----------------------------------------------------------------------------- NVML
class _NvmlMem(ctypes.Structure):
    _fields_ = [("total", c_uint64), ("free", c_uint64), ("used", c_uint64)]


def nvml_free(index):
    """VRAM reellement libre (tous programmes confondus) du GPU `index`, ou None."""
    try:
        nv = ctypes.CDLL("nvml.dll")
        if nv.nvmlInit_v2() != 0:
            return None
        h, mem = c_void_p(), _NvmlMem()
        ok = (nv.nvmlDeviceGetHandleByIndex_v2(c_uint(index), byref(h)) == 0
              and nv.nvmlDeviceGetMemoryInfo(h, byref(mem)) == 0)
        nv.nvmlShutdown()
        return mem.free if ok else None
    except OSError:
        return None


# ----------------------------------------------------------------------------- CUDA
class CudaError(RuntimeError):
    def __init__(self, name, code):
        super().__init__(f"{name} -> erreur CUDA {code}")
        self.code = code


class Cuda:
    def __init__(self):
        self.cu = ctypes.WinDLL("nvcuda.dll")

    def __call__(self, name, *args):
        r = getattr(self.cu, name)(*args)
        if r != 0:
            raise CudaError(name, r)


class GpuGuard:
    """Test et garde des blocs defectueux d'un GPU."""

    def __init__(self, cu, index):
        self.cu, self.index = cu, index
        dev = c_int()
        cu("cuDeviceGet", byref(dev), index)
        name = ctypes.create_string_buffer(256)
        cu("cuDeviceGetName", name, 256, dev)
        self.name = name.value.decode(errors="replace")
        self.ctx = c_void_p()
        cu("cuCtxCreate_v2", byref(self.ctx), c_uint(0), dev)
        mod = c_void_p()
        cu("cuModuleLoadData", byref(mod), ctypes.c_char_p(PTX + b"\0"))
        self.k_fill, self.k_check = c_void_p(), c_void_p()
        cu("cuModuleGetFunction", byref(self.k_fill), mod, b"fill")
        cu("cuModuleGetFunction", byref(self.k_check), mod, b"check")
        self.n_words = CHUNK // 4
        self.threads = 256
        self.blocks = (self.n_words + self.threads - 1) // self.threads
        self.cnt = c_uint64()
        cu("cuMemAlloc_v2", byref(self.cnt), c_size_t(4))
        f, t = c_size_t(), c_size_t()
        cu("cuMemGetInfo_v2", byref(f), byref(t))
        self.total = t.value
        self.kept = []
        self.self_test()

    def _cur(self):
        self.cu("cuCtxSetCurrent", self.ctx)

    def _launch(self, func, *args):
        params = (c_void_p * len(args))(*[ctypes.cast(byref(a), c_void_p) for a in args])
        self.cu("cuLaunchKernel", func, c_uint(self.blocks), c_uint(1), c_uint(1), c_uint(self.threads),
                c_uint(1), c_uint(1), c_uint(0), None, params, None)

    def _fill(self, ptr, seed):
        self._launch(self.k_fill, c_uint64(ptr), c_uint32(seed & 0xFFFFFFFF), c_uint32(self.n_words))

    def _errors(self, ptr, seed):
        self.cu("cuMemsetD32_v2", self.cnt, c_uint(0), c_size_t(1))
        self._launch(self.k_check, c_uint64(ptr), c_uint32(seed & 0xFFFFFFFF), c_uint32(self.n_words),
                     c_uint64(self.cnt.value))
        self.cu("cuCtxSynchronize")
        host = c_uint32()
        self.cu("cuMemcpyDtoH_v2", byref(host), self.cnt, c_size_t(4))
        return host.value

    def self_test(self):
        """Le testeur doit detecter un mauvais motif partout, sinon on ne lui fait pas confiance."""
        self._cur()
        p = c_uint64()
        self.cu("cuMemAlloc_v2", byref(p), c_size_t(CHUNK))
        self._fill(p.value, 1234)
        self.cu("cuCtxSynchronize")
        diff = self._errors(p.value, 4321)
        self.cu("cuMemFree_v2", p)
        if diff != self.n_words:
            raise RuntimeError(f"auto-test du testeur en echec sur {self.name} ({diff}/{self.n_words})")

    def scan(self, keep=True):
        """Teste la VRAM reellement libre. Retourne le nombre de blocs defectueux trouves."""
        self._cur()
        f, t = c_size_t(), c_size_t()
        self.cu("cuMemGetInfo_v2", byref(f), byref(t))
        real = nvml_free(self.index)
        avail = min(f.value, real) if real else f.value
        target = max(0, (avail - MARGIN) // CHUNK)
        t0 = time.time()
        chunks = []
        for _ in range(target):
            p = c_uint64()
            try:
                self.cu("cuMemAlloc_v2", byref(p), c_size_t(CHUNK))
            except CudaError:
                break
            chunks.append(p)
        bad = {}
        for seed in SEEDS:
            for i, p in enumerate(chunks):
                self._fill(p.value, seed ^ (i * 7919))
            self.cu("cuCtxSynchronize")
            for i, p in enumerate(chunks):
                e = self._errors(p.value, seed ^ (i * 7919))
                if e:
                    bad[i] = bad.get(i, 0) + e
        for i, p in enumerate(chunks):
            if keep and i in bad:
                self.kept.append(p)
            else:
                self.cu("cuMemFree_v2", p)
        self.cu("cuCtxSynchronize")
        detail = ", ".join(f"bloc {i}: {n} erreurs" for i, n in sorted(bad.items())) or "aucun"
        log(f"[GPU {self.index} {self.name}] {self.total / 2**30:.1f} Gio, test de {len(chunks) * 64} Mio "
            f"en {time.time() - t0:.0f} s : {len(bad)} bloc(s) defectueux [{detail}]"
            + (f" ; total garde {len(self.kept) * 64} Mio" if keep else " (test seul, rien n'est garde)"))
        return len(bad), len(chunks) * 64

    def periodic(self):
        """Un bloc defectueux n'est jamais libere (certains defauts sont des effets d'alias :
        teste seul, le bloc parait sain). Nouveau test complet quand la carte est presque
        libre (>= 75 %), au plus toutes les 30 min, pour rattraper une zone que Windows aurait
        liberee en deplacant de la memoire. Plafond : 16 blocs (1 Gio) par carte."""
        idle = (nvml_free(self.index) or 0) >= 0.75 * self.total
        if idle and len(self.kept) < 16 and time.time() - getattr(self, "last_scan", 0) >= 1800:
            self.scan()
            self.last_scan = time.time()


def init_cuda():
    cu = Cuda()
    for _ in range(20):          # le pilote peut ne pas etre pret juste apres l'ouverture de session
        try:
            cu("cuInit", c_uint(0))
            break
        except CudaError as e:
            log(f"pilote NVIDIA pas pret ({e}), nouvel essai dans 15 s")
            time.sleep(15)
    else:
        raise RuntimeError("pilote NVIDIA indisponible")
    n = c_int()
    cu("cuDeviceGetCount", byref(n))
    return cu, n.value


def write_status(guards):
    parts = [f"GPU {g.index} {g.name} : {len(g.kept)} bloc(s) defectueux garde(s) ({len(g.kept) * 64} Mio)"
             for g in guards]
    with open(STATUS, "w", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} protection active\n" + "\n".join(parts) + "\n")


def run_background():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.restype = c_void_p
    _m = k32.CreateMutexW(None, False, MUTEX)
    if ctypes.get_last_error() == 183:
        return
    try:
        cu, n = init_cuda()
        guards = [GpuGuard(cu, i) for i in range(n)]
        for g in guards:
            g.scan()
            g.last_scan = time.time()
        write_status(guards)
        k32.SetPriorityClass(k32.GetCurrentProcess(), 0x40)   # priorite basse
        while True:
            time.sleep(CHECK_EVERY)
            for g in guards:
                try:
                    g.periodic()
                except CudaError as e:
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
    cu, n = init_cuda()
    results = []
    for i in range(n):
        g = GpuGuard(cu, i)
        bad, tested = g.scan(keep=False)
        results.append((g.name, bad, tested))
    return results


# ----------------------------------------------------------------------------- installation
def exe_path():
    return sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)


def background_pids():
    """PID des instances --background (via WMIC/PowerShell, sans dependance)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"Name='VRAM-Guard.exe'\" | "
             "Where-Object { $_.CommandLine -like '*--background*' } | ForEach-Object { $_.ProcessId }"],
            capture_output=True, text=True, creationflags=0x08000000, timeout=20).stdout
        return [int(x) for x in out.split() if x.strip().isdigit()]
    except Exception:  # noqa: BLE001
        return []


def stop_background():
    for pid in background_pids():
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, creationflags=0x08000000)
    time.sleep(1)


def start_background():
    target = INSTALLED_EXE if os.path.exists(INSTALLED_EXE) else exe_path()
    subprocess.Popen([target, "--background"], creationflags=0x00000008 | 0x08000000, close_fds=True)


def install():
    stop_background()
    src = exe_path()
    if os.path.abspath(src).lower() != os.path.abspath(INSTALLED_EXE).lower():
        import shutil
        shutil.copy2(src, INSTALLED_EXE)
    ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{STARTUP_LNK}');"
          f"$s.TargetPath='{INSTALLED_EXE}';$s.Arguments='--background';$s.WorkingDirectory='{DATA}';"
          f"$s.Description='VRAM Guard : protection des zones defectueuses de la VRAM';$s.Save()")
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
    tk.Label(root, text="Protege votre carte NVIDIA contre ses zones de memoire video defectueuses\n"
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
                root.after(0, lambda: messagebox.showerror(APP, str(e)))
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
    elif "--test" in sys.argv:
        try:
            for name, bad, tested in run_test_only():
                print(f"{name}: {bad} bloc(s) defectueux sur {tested} Mio")
        except Exception as e:  # noqa: BLE001
            log(f"ERREUR test : {e!r}")
    else:
        run_gui()
