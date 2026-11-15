"""
Spotify Orbit & XAPK v2 Compatibility Simulator — Android Kivy Edition (main.py)
================================================================================
تطبيق أندرويد مبني بـ Kivy + asyncio لمحاكاة وتحليل حزم XAPK v2 (Spotify_+Music.zip)
وإقلاع المحرك الأصلي ARM64 (liborbit-jni-spotify.so / JNI_OnLoad / RegisterNatives).
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import queue
import struct
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, List, Optional

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.textinput import TextInput

try:
    from android.permissions import Permission, request_permissions  # type: ignore

    IS_ANDROID = True
except ImportError:
    IS_ANDROID = False


# ---------------------------------------------------------------------------
# 1. Structural Data Models
# ---------------------------------------------------------------------------


@dataclass
class SplitApkEntry:
    split_id: str
    filename: str
    declared_size: int
    compressed_size: int
    role: str


@dataclass
class DexHeaderInfo:
    name: str
    file_size: int
    compressed_size: int
    version: str
    string_ids_size: int
    type_ids_size: int
    proto_ids_size: int
    field_ids_size: int
    method_ids_size: int
    class_defs_size: int
    stored_uncompressed: bool


@dataclass
class ElfLibraryInfo:
    name: str
    size: int
    machine: str
    bits: int
    endian: str
    e_type: str
    phnum: int
    shnum: int
    jni_mode: str


@dataclass
class JniRegisteredMethod:
    library: str
    java_class: str
    method_name: str
    signature: str
    fn_ptr: str
    binding_mode: str


@dataclass
class XapkAnalysisReport:
    archive_path: str
    archive_size: int
    archive_sha256: str
    xapk_version: int
    package_name: str
    version_name: str
    version_code: str
    min_sdk: str
    target_sdk: str
    permissions_count: int
    split_entries: List[SplitApkEntry] = field(default_factory=list)
    dex_files: List[DexHeaderInfo] = field(default_factory=list)
    elf_libraries: List[ElfLibraryInfo] = field(default_factory=list)
    service_loaders: List[str] = field(default_factory=list)
    allow_list_entries: int = 0
    rcs_overrides_raw: str = "{}"


# ---------------------------------------------------------------------------
# 2. Nested Stream Reader & Binary Parsers (XAPK / MultiDex / ELF64)
# ---------------------------------------------------------------------------


class _StoredZipSubStream(io.RawIOBase):
    """Zero-copy seekable stream for ZIP_STORED nested APKs."""

    def __init__(self, path: str, data_offset: int, length: int) -> None:
        super().__init__()
        self._fp = open(path, "rb")
        self._start = data_offset
        self._length = length
        self._pos = 0
        self._fp.seek(self._start)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            target = offset
        elif whence == io.SEEK_CUR:
            target = self._pos + offset
        elif whence == io.SEEK_END:
            target = self._length + offset
        else:
            raise ValueError(f"Unsupported whence: {whence}")
        self._pos = max(0, min(self._length, target))
        self._fp.seek(self._start + self._pos)
        return self._pos

    def read(self, size: int = -1) -> bytes:
        remaining = self._length - self._pos
        if remaining <= 0:
            return b""
        to_read = remaining if size is None or size < 0 else min(size, remaining)
        data = self._fp.read(to_read)
        self._pos += len(data)
        return data

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self.read(len(buffer))
        n = len(data)
        buffer[:n] = data
        return n

    def close(self) -> None:
        if not self.closed:
            self._fp.close()
        super().close()


def _open_nested_apk(
    outer_path: str, outer_zip: zipfile.ZipFile, member_name: str
) -> tuple[zipfile.ZipFile, io.IOBase]:
    info = outer_zip.getinfo(member_name)
    if info.compress_type == zipfile.ZIP_STORED and info.file_size > 0:
        with open(outer_path, "rb") as raw_fp:
            raw_fp.seek(info.header_offset)
            lfh = raw_fp.read(30)
            if len(lfh) == 30 and lfh[:4] == b"PK\x03\x04":
                _, _, _, _, _, _, _, _, _, name_len, extra_len = struct.unpack(
                    "<4sHHHHHIIIHH", lfh
                )
                data_offset = info.header_offset + 30 + name_len + extra_len
                stream = _StoredZipSubStream(outer_path, data_offset, info.file_size)
                return zipfile.ZipFile(stream, "r"), stream
    mem_stream = io.BytesIO(outer_zip.read(member_name))
    return zipfile.ZipFile(mem_stream, "r"), mem_stream


def _parse_dex_header(name: str, header: bytes, zinfo: zipfile.ZipInfo) -> Optional[DexHeaderInfo]:
    if len(header) < 112 or not header.startswith(b"dex\n"):
        return None
    unpacked = struct.unpack("<8sI20s20I", header[:112])
    version = unpacked[0][4:7].decode("ascii", errors="replace")
    (
        file_size,
        _header_size,
        _endian_tag,
        _link_size,
        _link_off,
        _map_off,
        string_ids_size,
        _string_ids_off,
        type_ids_size,
        _type_ids_off,
        proto_ids_size,
        _proto_ids_off,
        field_ids_size,
        _field_ids_off,
        method_ids_size,
        _method_ids_off,
        class_defs_size,
        _class_defs_off,
        _data_size,
        _data_off,
    ) = unpacked[3:]

    return DexHeaderInfo(
        name=name,
        file_size=file_size,
        compressed_size=zinfo.compress_size,
        version=version,
        string_ids_size=string_ids_size,
        type_ids_size=type_ids_size,
        proto_ids_size=proto_ids_size,
        field_ids_size=field_ids_size,
        method_ids_size=method_ids_size,
        class_defs_size=class_defs_size,
        stored_uncompressed=(zinfo.compress_size == zinfo.file_size),
    )


def _parse_elf_header(name: str, header: bytes, size: int) -> Optional[ElfLibraryInfo]:
    if len(header) < 64 or header[:4] != b"\x7fELF":
        return None

    ei_class = header[4]
    ei_data = header[5]
    bits = 64 if ei_class == 2 else 32
    endian_prefix = "<" if ei_data == 1 else ">"
    endian_name = "Little-Endian" if ei_data == 1 else "Big-Endian"

    if bits == 64:
        (
            _ident,
            e_type_val,
            e_machine_val,
            _e_version,
            _e_entry,
            _e_phoff,
            _e_shoff,
            _e_flags,
            _e_ehsize,
            _e_phentsize,
            e_phnum,
            _e_shentsize,
            e_shnum,
            _e_shstrndx,
        ) = struct.unpack(f"{endian_prefix}16sHHIQQQIHHHHHH", header[:64])
    else:
        (
            _ident,
            e_type_val,
            e_machine_val,
            _e_version,
            _e_entry,
            _e_phoff,
            _e_shoff,
            _e_flags,
            _e_ehsize,
            _e_phentsize,
            e_phnum,
            _e_shentsize,
            e_shnum,
            _e_shstrndx,
        ) = struct.unpack(f"{endian_prefix}16sHHIIIIIHHHHHH", header[:52])

    machine_map = {183: "AArch64 (arm64-v8a)", 40: "ARM (armeabi-v7a)", 62: "x86_64", 3: "x86"}
    type_map = {2: "ET_EXEC", 3: "ET_DYN (Shared)"}

    base_name = os.path.basename(name)
    if base_name == "liborbit-jni-spotify.so":
        jni_mode = "Dynamic (JNI_OnLoad @ 0xb3b128)"
    elif base_name == "librootChecker.so":
        jni_mode = "Static (Java_com_ravelin_...)"
    elif "crashlytics" in base_name:
        jni_mode = "Signal Handler / NDK JNI"
    elif base_name == "libc++_shared.so":
        jni_mode = "LLVM C++ Runtime"
    else:
        jni_mode = "Native / JNI Support"

    return ElfLibraryInfo(
        name=base_name,
        size=size,
        machine=machine_map.get(e_machine_val, f"0x{e_machine_val:x}"),
        bits=bits,
        endian=endian_name,
        e_type=type_map.get(e_type_val, f"Type {e_type_val}"),
        phnum=e_phnum,
        shnum=e_shnum,
        jni_mode=jni_mode,
    )


def _compute_file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dex_sort_key(name: str) -> tuple[int, str]:
    stem = name[:-4]
    suffix = stem.replace("classes", "")
    return (1 if not suffix else int(suffix) if suffix.isdigit() else 999, name)


def _find_default_xapk() -> str:
    candidates = [
        Path("/sdcard/Download/Spotify_+Music.zip"),
        Path("/storage/emulated/0/Download/Spotify_+Music.zip"),
        Path.cwd() / "Spotify_+Music.zip",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return str(candidates[0] if IS_ANDROID else candidates[-1])


# ---------------------------------------------------------------------------
# 3. Asynchronous Orbit Compatibility Engine (asyncio Background Loop)
# ---------------------------------------------------------------------------


class OrbitAsyncEngine:
    """Runs XAPK parsing and native Orbit/Asio simulation on a background asyncio loop."""

    ORBIT_INIT_ARRAY_SAMPLE = [
        ("0x175d1c0", "0xb36244", "asio::system_context / orbit static ctor #0"),
        ("0x175d1c8", "0xb36878", "orbit::core::crypto_registry_init"),
        ("0x175d1d0", "0xae0380", "std::__ndk1::locale_runtime_init"),
        ("0x175d1d8", "0xb61b88", "orbit::audio::codec_pipeline_bootstrap"),
    ]

    DEFAULT_JNI_BINDINGS: List[JniRegisteredMethod] = [
        JniRegisteredMethod(
            "liborbit-jni-spotify.so",
            "com.spotify.orbit.NativeOrbitClient",
            "JNI_OnLoad",
            "(Lcom/spotify/orbit/JavaVM;Ljava/lang/Object;)I",
            "0xb3b128 (14,380 B)",
            "Entry / RegisterNatives",
        ),
        JniRegisteredMethod(
            "liborbit-jni-spotify.so",
            "com.spotify.orbit.NativeOrbitClient",
            "nativeCreateSession",
            "(Lcom/spotify/orbit/OrbitConfig;)J",
            "Dynamic via RegisterNatives",
            "RegisterNatives (JNI_OnLoad)",
        ),
        JniRegisteredMethod(
            "liborbit-jni-spotify.so",
            "com.spotify.orbit.NativeOrbitClient",
            "nativeStartAsioContext",
            "(J)V",
            "0x18a2928 (asio::system_context)",
            "RegisterNatives (JNI_OnLoad)",
        ),
        JniRegisteredMethod(
            "liborbit-jni-spotify.so",
            "com.spotify.orbit.NativeOrbitClient",
            "JNI_OnUnload",
            "(Lcom/spotify/orbit/JavaVM;Ljava/lang/Object;)V",
            "0xb3e954 (3,596 B)",
            "Teardown Hook",
        ),
        JniRegisteredMethod(
            "librootChecker.so",
            "com.ravelin.core.util.security.RootCheckerNative",
            "setLogDebugMessages",
            "(Z)V",
            "0xb70 (72 B)",
            "Static Export (.dynsym)",
        ),
        JniRegisteredMethod(
            "librootChecker.so",
            "com.ravelin.core.util.security.RootCheckerNative",
            "checkForRoot",
            "()Z",
            "0xc74 (384 B)",
            "Static Export (.dynsym)",
        ),
        JniRegisteredMethod(
            "librootChecker.so",
            "com.ravelin.core.util.security.RootCheckerNative",
            "isMagiskPresent",
            "()Z",
            "0xdf4 (440 B)",
            "Static Export (.dynsym)",
        ),
    ]

    def __init__(self, ui_queue: "queue.Queue[tuple[str, Any]]") -> None:
        self._ui_queue = ui_queue
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name="OrbitAsioWorker", daemon=True
        )
        self.report: Optional[XapkAnalysisReport] = None
        self.runtime_booted = False
        self.streaming_active = False
        self._stream_task: Optional[asyncio.Task[None]] = None
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _emit(self, event_type: str, payload: Any) -> None:
        self._ui_queue.put((event_type, payload))

    def _log(self, tag: str, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self._emit("log", f"[{timestamp}] [{tag}] {message}")

    def submit(self, coro_factory: Callable[[], Any]) -> None:
        asyncio.run_coroutine_threadsafe(coro_factory(), self._loop)

    async def analyze_xapk_bundle(self, archive_path: str) -> None:
        self._emit("status", "Analyzing XAPK v2, MultiDex & ARM64 ELF64...")
        self._log("PARSER", f"Opening container: {archive_path}")
        try:
            report = await asyncio.to_thread(self._parse_xapk_sync, archive_path)
            self.report = report
            self._log(
                "XAPK",
                f"Verified {report.package_name} v{report.version_name} "
                f"(Code {report.version_code}, SDK {report.min_sdk}->{report.target_sdk})",
            )
            self._log(
                "MULTIDEX",
                f"Parsed {len(report.dex_files)} DEX headers, {len(report.service_loaders)} R8 services (p.*)",
            )
            self._log(
                "ELF64",
                f"Detected {len(report.elf_libraries)} arm64-v8a native libraries",
            )
            self._emit("report", report)
            self._emit("jni_table", list(self.DEFAULT_JNI_BINDINGS))
            self._emit("status", "Analysis Complete — Ready to Boot Orbit")
        except Exception as exc:
            self._log("ERROR", f"Failed to parse bundle: {exc}")
            self._emit("error", str(exc))
            self._emit("status", "Analysis Failed")

    def _parse_xapk_sync(self, archive_path: str) -> XapkAnalysisReport:
        if not os.path.isfile(archive_path):
            raise FileNotFoundError(f"File not found: {archive_path}")

        archive_size = os.path.getsize(archive_path)
        archive_sha256 = _compute_file_sha256(archive_path)

        with zipfile.ZipFile(archive_path, "r") as outer_zip:
            manifest_data = json.loads(outer_zip.read("manifest.json").decode("utf-8"))
            split_id_map = {
                item["file"]: item["id"] for item in manifest_data.get("split_apks", [])
            }

            split_entries: List[SplitApkEntry] = []
            for zinfo in outer_zip.infolist():
                if not zinfo.filename.endswith(".apk"):
                    continue
                split_id = split_id_map.get(zinfo.filename, "split")
                role = self._classify_split_role(zinfo.filename, split_id)
                split_entries.append(
                    SplitApkEntry(
                        split_id=split_id,
                        filename=zinfo.filename,
                        declared_size=zinfo.file_size,
                        compressed_size=zinfo.compress_size,
                        role=role,
                    )
                )

            dex_files: List[DexHeaderInfo] = []
            service_loaders: List[str] = []
            allow_list_entries = 0
            rcs_overrides_raw = "{}"

            if "com.spotify.music.apk" in outer_zip.namelist():
                base_apk, base_stream = _open_nested_apk(
                    archive_path, outer_zip, "com.spotify.music.apk"
                )
                try:
                    for info in base_apk.infolist():
                        if info.filename.startswith("classes") and info.filename.endswith(".dex"):
                            with base_apk.open(info, "r") as dex_fp:
                                parsed = _parse_dex_header(info.filename, dex_fp.read(112), info)
                                if parsed:
                                    dex_files.append(parsed)
                        elif info.filename.startswith("META-INF/services/"):
                            service_loaders.append(info.filename)
                    dex_files.sort(key=lambda item: _dex_sort_key(item.name))
                    service_loaders.sort()

                    if "assets/app_remote_allow_list.csv" in base_apk.namelist():
                        allow_bytes = base_apk.read("assets/app_remote_allow_list.csv")
                        allow_list_entries = len(allow_bytes.decode("utf-8", errors="ignore").splitlines())
                    if "assets/rcs_overrides.json" in base_apk.namelist():
                        rcs_overrides_raw = base_apk.read("assets/rcs_overrides.json").decode(
                            "utf-8", errors="ignore"
                        )
                finally:
                    base_apk.close()
                    base_stream.close()

            elf_libraries: List[ElfLibraryInfo] = []
            if "config.arm64_v8a.apk" in outer_zip.namelist():
                abi_apk, abi_stream = _open_nested_apk(
                    archive_path, outer_zip, "config.arm64_v8a.apk"
                )
                try:
                    for info in abi_apk.infolist():
                        if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                            with abi_apk.open(info, "r") as so_fp:
                                elf_info = _parse_elf_header(
                                    info.filename, so_fp.read(64), info.file_size
                                )
                                if elf_info:
                                    elf_libraries.append(elf_info)
                    elf_libraries.sort(key=lambda item: item.size, reverse=True)
                finally:
                    abi_apk.close()
                    abi_stream.close()

        return XapkAnalysisReport(
            archive_path=archive_path,
            archive_size=archive_size,
            archive_sha256=archive_sha256,
            xapk_version=int(manifest_data.get("xapk_version", 2)),
            package_name=str(manifest_data.get("package_name", "unknown")),
            version_name=str(manifest_data.get("version_name", "unknown")),
            version_code=str(manifest_data.get("version_code", "unknown")),
            min_sdk=str(manifest_data.get("min_sdk_version", "?")),
            target_sdk=str(manifest_data.get("target_sdk_version", "?")),
            permissions_count=len(manifest_data.get("permissions", [])),
            split_entries=split_entries,
            dex_files=dex_files,
            elf_libraries=elf_libraries,
            service_loaders=service_loaders,
            allow_list_entries=allow_list_entries,
            rcs_overrides_raw=rcs_overrides_raw.strip() or "{}",
        )

    @staticmethod
    def _classify_split_role(filename: str, split_id: str) -> str:
        if split_id == "base":
            return "Base APK (DEX + Resources + Services)"
        if "arm64" in filename:
            return "Native ABI Split (ARM64 ELF64 .so)"
        if "xxhdpi" in filename or "xhdpi" in filename:
            return "Display Density Split (Graphics)"
        return "Localization Split"

    async def boot_orbit_runtime(self) -> None:
        if self.runtime_booted:
            self._log("ORBIT", "Runtime is already active.")
            return

        self._emit("status", "Booting Orbit Native Runtime (NDK r27c / JNI_OnLoad)...")
        self._log("LINKER", "dlopen('libc++_shared.so') -> 1.29 MB LLVM C++ runtime loaded")
        await asyncio.sleep(0.18)

        self._log("LINKER", "dlopen('liborbit-jni-spotify.so') -> running 1,491 DT_INIT_ARRAY ctors (@ 0x175d1c0)")
        for slot_va, target_va, desc in self.ORBIT_INIT_ARRAY_SAMPLE:
            await asyncio.sleep(0.12)
            self._log(".init_array", f"[{slot_va}] -> call {target_va} ({desc})")

        await asyncio.sleep(0.18)
        self._log("ASIO", "Initialized asio::detail::posix_global_impl<asio::system_context> @ 0x18a2928")

        await asyncio.sleep(0.20)
        self._log("JNI", "Calling JNI_OnLoad(JavaVM*, void*) @ 0xb3b128 (14,380 B) -> JNI_VERSION_1_6")
        self._log("JNI", "Bound NativeOrbitClient methods via JNIEnv::RegisterNatives")

        await asyncio.sleep(0.15)
        self._log("SECURITY", "librootChecker.so: checkForRoot() @ 0xc74 = False | isMagiskPresent() @ 0xdf4 = False")

        self.runtime_booted = True
        self._emit("runtime_state", True)
        self._emit("status", "Orbit Runtime Active (JNI_OnLoad complete)")

    async def start_concurrent_simulation(self, track_uri: str) -> None:
        if not self.runtime_booted:
            await self.boot_orbit_runtime()

        if self.streaming_active:
            self._log("STREAM", "Concurrent Asio pipeline is already running.")
            return

        self.streaming_active = True
        self._emit("status", f"Running concurrent Asio tasks for {track_uri}")
        self._stream_task = asyncio.create_task(self._concurrent_pipeline(track_uri))

    async def _concurrent_pipeline(self, track_uri: str) -> None:
        try:
            await asyncio.gather(
                self._task_asio_audio_stream(track_uri),
                self._task_app_remote_ipc_guard(),
                self._task_rive_and_telemetry_loop(),
            )
            self._log("PIPELINE", "Concurrent streaming cycle completed cleanly.")
            self._emit("status", "Concurrent Streaming Cycle Complete")
        except asyncio.CancelledError:
            self._log("PIPELINE", "Streaming tasks cancelled.")
        finally:
            self.streaming_active = False

    async def _task_asio_audio_stream(self, track_uri: str) -> None:
        self._log("ASIO-IO", f"Starting non-blocking audio stream for: {track_uri}")
        for chunk in range(1, 6):
            await asyncio.sleep(0.35)
            self._log("AUDIO-BUF", f"Decoded & queued chunk #{chunk}/5 ({chunk * 256} KB) via asio::system_context")

    async def _task_app_remote_ipc_guard(self) -> None:
        allow_count = self.report.allow_list_entries if self.report else 0
        self._log("IPC-GUARD", f"Checking app_remote_allow_list.csv ({allow_count} rows) for SECURED_BROADCAST")
        await asyncio.sleep(0.55)
        self._log("IPC-GUARD", "App Remote SDK channel verified (OK)")

    async def _task_rive_and_telemetry_loop(self) -> None:
        for tick in range(1, 4):
            await asyncio.sleep(0.45)
            self._log("RIVE/TELEM", f"librive-android.so frame tick #{tick} + libcomScore.so heartbeat")

    async def shutdown_orbit_runtime(self) -> None:
        if self._stream_task and not self._stream_task.done():
            self._stream_task.cancel()
            try:
                await self._stream_task
            except asyncio.CancelledError:
                pass

        if self.runtime_booted:
            self._log("ASIO", "Stopping asio::system_context worker threads...")
            await asyncio.sleep(0.15)
            self._log("JNI", "Calling JNI_OnUnload(JavaVM*, void*) @ 0xb3e954 (3,596 B)")
            self.runtime_booted = False
            self._emit("runtime_state", False)

        self._emit("status", "Orbit Runtime Shutdown Complete")


# ---------------------------------------------------------------------------
# 4. Kivy Touch-Friendly Dark UI (Spotify Theme)
# ---------------------------------------------------------------------------


def _paint_bg(widget: Any, rgba: tuple[float, float, float, float]) -> None:
    with widget.canvas.before:
        Color(*rgba)
        rect = Rectangle(pos=widget.pos, size=widget.size)

    def _sync(instance: Any, _val: Any) -> None:
        rect.pos = instance.pos
        rect.size = instance.size

    widget.bind(pos=_sync, size=_sync)


class OrbitKivyApp(App):
    """Modern dark-themed Android Kivy application for the Orbit simulator."""

    C_BG = (0.071, 0.071, 0.071, 1)       # #121212
    C_CARD = (0.094, 0.094, 0.094, 1)     # #181818
    C_ELEV = (0.141, 0.141, 0.141, 1)     # #242424
    C_ACCENT = (0.114, 0.725, 0.329, 1)   # #1DB954
    C_TEXT = (1, 1, 1, 1)                 # #FFFFFF
    C_MUTED = (0.70, 0.70, 0.70, 1)       # #B3B3B3

    def build(self) -> BoxLayout:
        self.title = "Spotify Orbit & XAPK v2 Simulator"
        Window.clearcolor = self.C_BG

        if IS_ANDROID:
            request_permissions(
                [Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE]
            )

        self.ui_queue: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self.engine = OrbitAsyncEngine(self.ui_queue)

        root = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(8))

        # --- Header Card ---
        header = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(130), padding=dp(10), spacing=dp(6))
        _paint_bg(header, self.C_CARD)

        top_bar = BoxLayout(size_hint_y=None, height=dp(28))
        top_bar.add_widget(Label(text="Spotify Orbit & XAPK v2 Simulator", bold=True, font_size=dp(16), color=self.C_TEXT, halign="left", valign="middle"))
        self.runtime_lbl = Label(text="[Offline]", bold=True, font_size=dp(13), color=self.C_MUTED, size_hint_x=None, width=dp(120))
        top_bar.add_widget(self.runtime_lbl)
        header.add_widget(top_bar)

        path_bar = BoxLayout(size_hint_y=None, height=dp(38), spacing=dp(6))
        self.path_input = TextInput(
            text=_find_default_xapk(),
            multiline=False,
            background_color=self.C_ELEV,
            foreground_color=self.C_TEXT,
            cursor_color=self.C_ACCENT,
            font_size=dp(12),
            padding=[dp(8), dp(8)],
        )
        browse_btn = Button(text="Browse", size_hint_x=None, width=dp(84), background_normal="", background_color=self.C_ELEV, color=self.C_TEXT, bold=True)
        browse_btn.bind(on_release=self._open_file_chooser)
        path_bar.add_widget(self.path_input)
        path_bar.add_widget(browse_btn)
        header.add_widget(path_bar)

        self.meta_lbl = Label(
            text="Ready — Select Spotify_+Music.zip to inspect structure",
            font_size=dp(11),
            color=self.C_ACCENT,
            halign="left",
            valign="middle",
        )
        self.meta_lbl.bind(size=lambda lbl, s: setattr(lbl, "text_size", (s[0], None)))
        header.add_widget(self.meta_lbl)
        root.add_widget(header)

        # --- Action Buttons Grid (Touch Friendly) ---
        actions = GridLayout(cols=2, size_hint_y=None, height=dp(88), spacing=dp(6))
        btn_specs = [
            ("1. Analyze XAPK / DEX / ELF", self.C_ACCENT, (0, 0, 0, 1), self._on_analyze),
            ("2. Boot Orbit (JNI_OnLoad)", self.C_ELEV, self.C_TEXT, self._on_boot),
            ("3. Run Asio Stream Loop", self.C_ELEV, self.C_TEXT, self._on_stream),
            ("4. Shutdown (JNI_OnUnload)", self.C_ELEV, self.C_TEXT, self._on_shutdown),
        ]
        for label_text, bg_col, fg_col, callback in btn_specs:
            btn = Button(text=label_text, background_normal="", background_color=bg_col, color=fg_col, bold=True, font_size=dp(12))
            btn.bind(on_release=callback)
            actions.add_widget(btn)
        root.add_widget(actions)

        # --- Tabbed Content ---
        tabs = TabbedPanel(do_default_tab=False, tab_width=dp(105), background_color=self.C_BG)

        self.splits_grid = self._make_table_tab(tabs, "Splits (19)")
        self.dex_grid = self._make_table_tab(tabs, "MultiDex (15)")
        self.native_grid = self._make_table_tab(tabs, "ARM64 ELF & JNI")

        console_tab = TabbedPanelItem(text="Asyncio Console")
        self.console_input = TextInput(
            text="",
            readonly=True,
            background_color=(0.04, 0.04, 0.04, 1),
            foreground_color=(0.88, 0.88, 0.88, 1),
            font_size=dp(11),
            padding=[dp(8), dp(8)],
        )
        console_tab.add_widget(self.console_input)
        tabs.add_widget(console_tab)

        root.add_widget(tabs)

        # --- Status Bar ---
        self.status_lbl = Label(text="Status: Idle", size_hint_y=None, height=dp(24), font_size=dp(11), color=self.C_MUTED, halign="left")
        self.status_lbl.bind(size=lambda lbl, s: setattr(lbl, "text_size", (s[0], None)))
        root.add_widget(self.status_lbl)

        Clock.schedule_interval(self._poll_events, 0.06)
        if os.path.isfile(self.path_input.text.strip()):
            Clock.schedule_once(lambda _dt: self._on_analyze(None), 0.3)

        return root

    def _make_table_tab(self, tabs: TabbedPanel, title: str) -> GridLayout:
        tab = TabbedPanelItem(text=title)
        scroll = ScrollView(do_scroll_x=False, do_scroll_y=True)
        _paint_bg(scroll, self.C_CARD)
        grid = GridLayout(cols=1, size_hint_y=None, spacing=dp(4), padding=dp(8))
        grid.bind(minimum_height=grid.setter("height"))
        scroll.add_widget(grid)
        tab.add_widget(scroll)
        tabs.add_widget(tab)
        return grid

    def _add_card_row(self, grid: GridLayout, title: str, subtitle: str, accent: bool = False) -> None:
        row = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(54), padding=[dp(8), dp(4)])
        _paint_bg(row, self.C_ELEV)
        lbl1 = Label(text=title, bold=True, font_size=dp(12), color=self.C_ACCENT if accent else self.C_TEXT, halign="left", valign="middle")
        lbl1.bind(size=lambda l, s: setattr(l, "text_size", (s[0], None)))
        lbl2 = Label(text=subtitle, font_size=dp(10), color=self.C_MUTED, halign="left", valign="middle")
        lbl2.bind(size=lambda l, s: setattr(l, "text_size", (s[0], None)))
        row.add_widget(lbl1)
        row.add_widget(lbl2)
        grid.add_widget(row)

    def _open_file_chooser(self, _instance: Any) -> None:
        start_dir = "/sdcard/Download" if IS_ANDROID and os.path.isdir("/sdcard/Download") else str(Path.cwd())
        chooser = FileChooserListView(path=start_dir, filters=["*.zip", "*.xapk"])
        box = BoxLayout(orientation="vertical", spacing=dp(6), padding=dp(6))
        box.add_widget(chooser)

        btn_row = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(6))
        popup = Popup(title="Select Spotify_+Music.zip", content=box, size_hint=(0.92, 0.85))

        def _select(_btn: Any) -> None:
            if chooser.selection:
                self.path_input.text = chooser.selection[0]
            popup.dismiss()

        ok_btn = Button(text="Select", background_normal="", background_color=self.C_ACCENT, color=(0, 0, 0, 1), bold=True)
        ok_btn.bind(on_release=_select)
        cancel_btn = Button(text="Cancel", background_normal="", background_color=self.C_ELEV, color=self.C_TEXT)
        cancel_btn.bind(on_release=lambda _b: popup.dismiss())
        btn_row.add_widget(ok_btn)
        btn_row.add_widget(cancel_btn)
        box.add_widget(btn_row)
        popup.open()

    def _on_analyze(self, _instance: Any) -> None:
        path = self.path_input.text.strip()
        self.engine.submit(lambda: self.engine.analyze_xapk_bundle(path))

    def _on_boot(self, _instance: Any) -> None:
        self.engine.submit(self.engine.boot_orbit_runtime)

    def _on_stream(self, _instance: Any) -> None:
        self.engine.submit(
            lambda: self.engine.start_concurrent_simulation("spotify:track:4uLU6hMCjMI75M1A2tKUQC")
        )

    def _on_shutdown(self, _instance: Any) -> None:
        self.engine.submit(self.engine.shutdown_orbit_runtime)

    def _poll_events(self, _dt: float) -> None:
        try:
            while True:
                event_type, payload = self.ui_queue.get_nowait()
                self._handle_event(event_type, payload)
        except queue.Empty:
            pass

    def _handle_event(self, event_type: str, payload: Any) -> None:
        if event_type == "log":
            self.console_input.text += payload + "\n"
            self.console_input.cursor = (0, len(self.console_input.text.splitlines()))
        elif event_type == "status":
            self.status_lbl.text = f"Status: {payload}"
        elif event_type == "runtime_state":
            active = bool(payload)
            self.runtime_lbl.text = "[Orbit Active]" if active else "[Offline]"
            self.runtime_lbl.color = self.C_ACCENT if active else self.C_MUTED
        elif event_type == "report":
            self._render_report(payload)
        elif event_type == "jni_table":
            self._render_jni_section(payload)
        elif event_type == "error":
            self.status_lbl.text = f"Error: {payload}"

    def _render_report(self, report: XapkAnalysisReport) -> None:
        self.meta_lbl.text = (
            f"{report.package_name} v{report.version_name} (Code {report.version_code}) | "
            f"SDK {report.min_sdk}-{report.target_sdk} | Splits: {len(report.split_entries)} | "
            f"DEX: {len(report.dex_files)} | ELF64: {len(report.elf_libraries)}"
        )

        self.splits_grid.clear_widgets()
        for entry in report.split_entries:
            size_mb = entry.declared_size / (1024 * 1024)
            self._add_card_row(
                self.splits_grid,
                f"[{entry.split_id}] {entry.filename} ({size_mb:.2f} MB)",
                entry.role,
                accent=(entry.split_id == "base"),
            )

        self.dex_grid.clear_widgets()
        for dex in report.dex_files:
            size_mb = dex.file_size / (1024 * 1024)
            mode = "STORE (mmap)" if dex.stored_uncompressed else "DEFLATE"
            self._add_card_row(
                self.dex_grid,
                f"{dex.name} — DEX {dex.version} ({size_mb:.2f} MB) [{mode}]",
                f"Strings: {dex.string_ids_size:,} | Types: {dex.type_ids_size:,} | Methods: {dex.method_ids_size:,} | Classes: {dex.class_defs_size:,}",
                accent=(dex.name == "classes.dex"),
            )

        self.native_grid.clear_widgets()
        for lib in report.elf_libraries:
            self._add_card_row(
                self.native_grid,
                f"{lib.name} ({lib.size / 1024:,.1f} KB) — {lib.machine}",
                f"{lib.e_type} | PH/SH: {lib.phnum}/{lib.shnum} | {lib.jni_mode}",
                accent=(lib.name in ("liborbit-jni-spotify.so", "librootChecker.so")),
            )

    def _render_jni_section(self, methods: List[JniRegisteredMethod]) -> None:
        self._add_card_row(
            self.native_grid,
            "--- JNI Bindings (RegisterNatives & Static .dynsym) ---",
            "Verified entry points from REA MCP structural analysis",
            accent=True,
        )
        for item in methods:
            self._add_card_row(
                self.native_grid,
                f"{item.library} :: {item.method_name} @ {item.fn_ptr}",
                f"{item.java_class} | {item.signature} | {item.binding_mode}",
            )


if __name__ == "__main__":
    OrbitKivyApp().run()
