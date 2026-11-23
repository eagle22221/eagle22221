"""Static detection of protection and evasion techniques.

This answers "what is this program doing to hide from, or reach into, the
rest of the system?" — the view a malware analyst takes, and the one you need
to dissect a game cheat (what does this .exe do to my machine?) or an
anti-cheat (what techniques does it use?). The same techniques appear in
anti-cheat, DRM, cheats and malware, so binspect only *identifies and
explains* them. It never disables, bypasses or defeats anything.

Everything here is read from the already-parsed Binary: imports, section
names and entropy, subsystem, strings and overlay. The file is never run.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import strings as strings_mod
from .model import Binary

# category -> (title, plain-language explanation)
CATEGORIES: Dict[str, Tuple[str, str]] = {
    "packing": (
        "Packing or protection",
        "The program's code is compressed or protected, so most of it cannot "
        "be read until the program unpacks itself in memory at run time. "
        "Packers and protectors are used by anti-cheat, DRM and malware alike; "
        "to read the real code you would run it under a debugger and dump it."),
    "anti-debug": (
        "Anti-debugging",
        "The program checks whether it is being debugged and can hide, change "
        "its behaviour or refuse to run. Common in anti-cheat, DRM and malware."),
    "anti-vm": (
        "Virtual-machine or sandbox checks",
        "The program looks for signs that it is running in a virtual machine "
        "or an analysis sandbox, which it may use to behave differently when "
        "watched."),
    "injection": (
        "Process injection",
        "The program can write code or data into another running process and "
        "execute it. Game cheats use this to get inside a game; some anti-cheat "
        "and much malware use it too."),
    "hooking": (
        "API or input hooking",
        "The program can intercept calls, messages or input that belong to "
        "other software. Used by overlays, cheats, key loggers and anti-cheat."),
    "driver": (
        "Kernel driver",
        "The program talks to, or is, a kernel-mode driver, giving it deep "
        "access to the whole system. Modern anti-cheat and some cheats ship a "
        "driver for this reach."),
    "overlay": (
        "Appended data",
        "Extra data is stored after the end of the program itself. Installers "
        "and self-extracting or self-modifying programs keep payloads here; it "
        "is worth extracting and inspecting."),
}


@dataclass
class Technique:
    category: str
    title: str
    confidence: str                 # "high" | "medium"
    evidence: List[str] = field(default_factory=list)
    explanation: str = ""


# --- import name tables (all matched case-insensitively) -----------------------

_ANTI_DEBUG = {
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "ntsetinformationthread", "debugactiveprocess", "ntqueryobject", "ntclose",
    "outputdebugstringa", "outputdebugstringw", "rtladjustprivilege",
    "dbgbreakpoint", "dbguiremotebreakin", "blockinput", "ptrace",
}
# imports that only hint at anti-debugging (timing side-channels, common logging)
_ANTI_DEBUG_WEAK = {
    "gettickcount", "gettickcount64", "queryperformancecounter", "timegettime",
    "ntclose", "outputdebugstringa", "outputdebugstringw",
}
_INJECTION = {
    "virtualallocex", "virtualprotectex", "writeprocessmemory", "createremotethread",
    "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc", "ntqueueapcthread",
    "ntmapviewofsection", "setthreadcontext", "ntsetcontextthread",
    "ntwritevirtualmemory", "zwwritevirtualmemory", "process_vm_writev",
    "createremotethreadex",
}
_HOOKING = {
    "setwindowshookexa", "setwindowshookexw", "setwineventhook",
    "unhookwindowshookex", "callnexthookex",
}
# libraries that only a kernel-mode driver imports from
_DRIVER_LIBS = {"ntoskrnl.exe", "hal.dll", "wdfldr.sys", "ndis.sys", "fltmgr.sys",
                "ksecdd.sys", "wdf01000.sys", "storport.sys"}

# packer / protector section-name signatures -> product name
_PACKER_SECTIONS: List[Tuple[str, str]] = [
    ("upx", "UPX"), (".vmp", "VMProtect"), ("vmp0", "VMProtect"), ("vmp1", "VMProtect"),
    (".themida", "Themida"), (".winlice", "Themida/WinLicense"), ("winlicen", "Themida/WinLicense"),
    (".enigma", "Enigma Protector"), ("enigma", "Enigma Protector"),
    (".aspack", "ASPack"), ("aspack", "ASPack"), (".adata", "ASPack"),
    (".petite", "Petite"), ("petite", "Petite"),
    (".mpress", "MPRESS"), ("mpress", "MPRESS"),
    (".fsg", "FSG"), ("fsg!", "FSG"), (".nsp", "NsPack"), ("nsp0", "NsPack"),
    ("molebox", "MoleBox"), (".boom", "The Boomerang"), (".perplex", "Perplex"),
    (".y0da", "yoda's crypter"), (".pelock", "PELock"), (".pack", "generic packer"),
    (".rmnet", "packer"), (".taz", "PESpin"),
]

# virtual-machine / sandbox ARTIFACT marker -> vendor family. These are driver,
# service and device names, not plain vendor words like "VMware" or "KVM" that
# show up in ordinary software (compilers, container tools) and cause false hits.
_VM_MARKERS: List[Tuple[str, str]] = [
    ("VBoxGuest", "vbox"), ("vboxservice", "vbox"), ("vboxtray", "vbox"),
    ("VBoxSF", "vbox"), ("VBoxMouse", "vbox"), ("VBoxVideo", "vbox"),
    ("VBoxMiniRdr", "vbox"), ("vboxdisp", "vbox"),
    ("vmci.sys", "vmware"), ("vmtoolsd", "vmware"), ("vmwaretray", "vmware"),
    ("vmwareuser", "vmware"), ("vmmouse.sys", "vmware"), ("vmhgfs", "vmware"),
    ("vmware-vmx", "vmware"),
    ("qemu-ga", "qemu"), ("qemuwmi", "qemu"),
    ("xenservice", "xen"), ("xenvbd", "xen"), ("xennet", "xen"),
    ("SbieDll.dll", "sandbox"), ("sbiedll", "sandbox"), ("cuckoomon", "sandbox"),
    ("sandboxiedcomlaunch", "sandbox"),
    ("prl_cc", "parallels"), ("prltools", "parallels"),
]

_HIGH_ENTROPY = 7.2


def _imports(binary: Binary) -> Dict[str, str]:
    """Flagged-lookup helper: lowercase import name -> original spelling."""
    names: Dict[str, str] = {}
    for imp in binary.imports:
        if imp.name and not imp.name.startswith("#"):
            names.setdefault(imp.name.lower(), imp.name)
    return names


def _from_imports(found: Dict[str, str], wanted: set) -> List[str]:
    return sorted(original for lower, original in found.items() if lower in wanted)


def analyze(binary: Binary) -> List[Technique]:
    """Techniques the binary shows, most interesting categories first (by name).
    An empty list means nothing notable was found."""
    out: List[Technique] = []
    imports = _imports(binary)

    def add(category: str, confidence: str, evidence: List[str]) -> None:
        title, explanation = CATEGORIES[category]
        out.append(Technique(category, title, confidence, evidence, explanation))

    # -- packing / protectors ------------------------------------------------
    # Only precise signals: a known packer section name, an *executable*
    # high-entropy section (encrypted/compressed code), or the entry point
    # landing in a high-entropy section. Plain high-entropy data (embedded
    # compressed assets) is common in normal programs, so it is not enough.
    packer_evidence: List[str] = []
    entry_sec = binary.section_at(binary.entry) if binary.entry is not None else None
    for s in binary.sections:
        if not s.size or s.size < 64:
            continue
        low = (s.name or "").lower()
        product = next((name for sig, name in _PACKER_SECTIONS if low.startswith(sig)
                        or low == sig.strip(".")), None)
        entropy = binary.section_entropy(s)
        if product:
            packer_evidence.append(f'section "{s.name}" ({product})')
            if entropy > _HIGH_ENTROPY:
                packer_evidence.append(f'section "{s.name}" entropy {entropy:.2f} of 8')
        elif entropy > _HIGH_ENTROPY and "x" in s.perms:
            packer_evidence.append(
                f'executable section "{s.name}" entropy {entropy:.2f} of 8')
    if not packer_evidence and entry_sec is not None:
        entry_entropy = binary.section_entropy(entry_sec)
        if entry_entropy > _HIGH_ENTROPY:
            packer_evidence.append(
                f'entry point is in high-entropy section "{entry_sec.name}" '
                f'({entry_entropy:.2f} of 8)')
    if packer_evidence:
        add("packing", "high", packer_evidence)

    # -- anti-debugging ------------------------------------------------------
    debug = _from_imports(imports, _ANTI_DEBUG | _ANTI_DEBUG_WEAK)
    if debug:
        strong = any(name.lower() in _ANTI_DEBUG and name.lower() not in _ANTI_DEBUG_WEAK
                     for name in debug)
        add("anti-debug", "high" if strong else "medium",
            [f"imports {name}" for name in debug])

    # -- anti-vm / sandbox ---------------------------------------------------
    vm = _vm_markers(binary)
    if vm:
        families = {family for _marker, family in vm}
        evidence = sorted(f'string "{marker}"' for marker, _family in vm)
        add("anti-vm", "high" if len(families) >= 3 else "medium", evidence)

    # -- process injection ---------------------------------------------------
    inject = _from_imports(imports, _INJECTION)
    if inject:
        add("injection", "high" if len(inject) >= 2 else "medium",
            [f"imports {name}" for name in inject])

    # -- hooking -------------------------------------------------------------
    hook = _from_imports(imports, _HOOKING)
    if hook:
        add("hooking", "high", [f"imports {name}" for name in hook])

    # -- kernel driver -------------------------------------------------------
    driver_evidence: List[str] = []
    if binary.kind == "driver" or binary.metadata.get("subsystem") in ("native",):
        driver_evidence.append("native subsystem (kernel-mode driver)")
    driver_evidence += [f"imports from {lib}" for lib in binary.libraries
                        if lib.lower() in _DRIVER_LIBS]
    if driver_evidence:
        add("driver", "high", driver_evidence)
    elif "deviceiocontrol" in imports:
        add("driver", "medium", [f"imports {imports['deviceiocontrol']}"])

    # -- overlay -------------------------------------------------------------
    overlay = binary.metadata.get("overlay")
    if isinstance(overlay, dict) and overlay.get("size", 0) > 256:
        add("overlay", "medium",
            [f"appended data: {overlay['size']} bytes at offset {overlay['offset']:#x}"])

    out.sort(key=lambda t: t.category)
    return out


def _vm_markers(binary: Binary) -> List[Tuple[str, str]]:
    """(marker, family) pairs whose marker appears in a readable string.
    Strings inside packed/high-entropy sections are skipped so random bytes
    cannot masquerade as markers."""
    noisy = {s.name for s in binary.sections
             if s.size >= 64 and binary.section_entropy(s) > 7.0}
    seen: Dict[str, str] = {}
    for s in strings_mod.extract(binary, min_length=4):
        if s.section in noisy:
            continue
        text = s.text.lower()
        for marker, family in _VM_MARKERS:
            if marker.lower() in text:
                seen.setdefault(marker, family)
    return sorted(seen.items())
