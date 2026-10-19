import sys
sys.dont_write_bytecode = True

import argparse
import collections
import ctypes
import json
import os
import pathlib
import shutil
import signal
import sqlite3
import struct
import subprocess
import tempfile
import time
from contextlib import closing, nullcontext
from ctypes import wintypes
from pathlib import Path

from TestSupport import Collector, open_trace, path_parser, run_paths, run_scenarios, values, wait_file


def sibling_target(target_path):
    directory = target_path.parent
    candidates = [directory / "x86" / target_path.name]
    if directory.name.lower() == "x86":
        candidates.append(directory.parent / target_path.name)
    for ancestor in directory.parents:
        if (name := ancestor.name.lower()) in ("x64", "x86"):
            sibling = ancestor.with_name("x86" if name == "x64" else "x64")
            candidates.append(sibling / "bin" / directory.name / target_path.name)
    return next((candidate for candidate in candidates if candidate.exists()), None)


kernel = ctypes.WinDLL("kernel32", use_last_error=True)
user = ctypes.WinDLL("user32", use_last_error=True)
kernel.AttachConsole.argtypes = [wintypes.DWORD]
kernel.GetConsoleWindow.restype = wintypes.HWND
kernel.GetStdHandle.argtypes = [wintypes.DWORD]
kernel.GetStdHandle.restype = wintypes.HANDLE
kernel.SetStdHandle.argtypes = [wintypes.DWORD, wintypes.HANDLE]
kernel.GetConsoleProcessList.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.OpenProcess.restype = wintypes.HANDLE
kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
user.IsWindowVisible.argtypes = [wintypes.HWND]
user.IsIconic.argtypes = [wintypes.HWND]
user.GetForegroundWindow.restype = wintypes.HWND
user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]


def check_collector(collector_path, target_path):
    with tempfile.TemporaryDirectory(prefix="Detourist-IPC-\u0394-") as temporary:
        root = pathlib.Path(temporary)
        collector = Collector(collector_path)
        target = None
        try:
            hello = collector.call("hello")
            assert hello["protocol"] == 1
            catalog = {api["name"]: api for api in hello["catalog"]}
            assert catalog["WriteFile"]["argumentCount"] == 5
            collector.process.stdin.write("{malformed request}\n")
            collector.process.stdin.flush()
            malformed = collector.responses.get(timeout=5)
            assert malformed["ok"] is False and malformed["id"] is None, malformed
            assert collector.call("status")["finished"]
            assert "Unknown" in collector.call("invalid-command", expected=False)
            assert collector.call("pause", expected=False, paused=True)
            assert collector.call("page", expected=False, database=str(root / "missing.db"))
            assert any(process["pid"] == os.getpid() for process in collector.call("processes"))

            # A launched child and its decoded buffers remain queryable after the target exits.
            database = str(root / "launched.db")
            status = collector.capture(database=database, executable=str(target_path), arguments="--child 20",
                                       bufferLimit=64, apiMask=hello["allApis"], followChildren=True)
            assert status["calls"] > 0 and status["processes"] == 2 and not status["partial"], status
            # A complete view seeks through bounded IPC batches without dropping or duplicating calls.
            query = {"database": database, "limit": 1000}
            all_calls = []
            while True:
                batch = collector.call("page", **query)
                if not all_calls:
                    assert batch["totalCalls"] == status["calls"], batch["totalCalls"]
                    newest = batch["calls"][0]
                    query.update(newestTimestamp=newest["started"], newestTarget=newest["target"],
                                 newestCallId=newest["id"])
                else:
                    assert not batch["targets"] and not batch["threads"], batch
                all_calls.extend(batch["calls"])
                if len(batch["calls"]) < query["limit"]:
                    break
                oldest = batch["calls"][-1]
                query.update(beforeTimestamp=oldest["started"], beforeTarget=oldest["target"],
                             beforeCallId=oldest["id"], includeMetadata=False)
            assert len(all_calls) == status["calls"] > 1000, (len(all_calls), status)
            identities = [(call["started"], call["target"], call["id"]) for call in all_calls]
            assert identities == sorted(set(identities), reverse=True), "Complete view lost call order or uniqueness"

            # An indexed view addresses the same calls by position, in either order and under display filters.
            def identity(call):
                return call["started"], call["target"], call["id"]

            state, rows = collector.view(database)
            assert [identity(call) for call in rows] == identities and state["totalCalls"] == status["calls"], state
            assert len(state["targets"]) == 2 and {thread["target"] for thread in state["threads"]} == {
                target["id"] for target in state["targets"]}, state
            assert all("summary" in call and call["depth"] >= 0 for call in rows)
            probe = rows[len(rows) // 2]
            assert collector.call("locate", view=state["view"], target=probe["target"],
                                  callId=probe["id"])["index"] == len(rows) // 2
            assert collector.call("rows", view=state["view"], index=len(rows), limit=10)["calls"] == []
            assert [identity(call) for call in collector.view(database, "oldest")[1]] == identities[::-1]
            for text, keep in (
                    ("WriteFile", lambda call: "writefile" in call["name"].lower()),
                    ("-WriteFile ntdll!", lambda call: "writefile" not in call["name"].lower()
                     and "ntdll" in call["module"].lower()),
                    ("=WriteFile|Nt*File", lambda call: call["name"] == "WriteFile" or (
                        call["name"].lower().startswith("nt") and call["name"].lower().endswith("file"))),
                    ("depth:0", lambda call: call["depth"] == 0)):
                matching = collector.view(database, filter=text)[1]
                assert [identity(call) for call in matching] == [
                    identity(call) for call in all_calls if keep(call)], text
            assert [identity(call) for call in collector.view(database, failuresOnly=True)[1]] == [
                identity(call) for call in all_calls if call["flags"] & 1]
            registry = collector.view(database, filter="text:software")[1]
            assert registry and any(call["name"] == "RegOpenKeyExW" for call in registry), len(registry)
            sized = collector.view(database, filter="arg:2048")[1]
            assert any(call["name"] == "WriteFile" for call in sized) and len(sized) < len(all_calls), len(sized)
            slowest = collector.view(database, "slowest")[1]
            durations = [call["durationUs"] for call in slowest]
            assert durations == sorted(durations, reverse=True) and len(slowest) == sum(
                call["durationUs"] >= 0 for call in all_calls), len(slowest)
            assert "Filter" in collector.call("view", expected=False, database=database, filter="tid:none")
            assert "no longer available" in collector.call("rows", expected=False, view=state["view"] + 1000)
            trace = sqlite3.connect(f"file:{pathlib.Path(database).as_posix()}?mode=ro", uri=True)
            indexes = {row[0] for row in trace.execute("SELECT name FROM sqlite_master WHERE type='index'")}
            trace.close()
            assert {"calls_failed", "calls_pending"} <= indexes, indexes
            page = collector.call("page", database=database, api="WriteFile", limit=10)
            assert len(page["calls"]) == 10 and len(page["targets"]) == 2, page
            # Select file payloads explicitly because the target also reports its results to the console.
            details = [collector.call("details", database=database, target=call["target"], callId=call["id"])
                       for call in page["calls"]]
            detail = next(value for value in details if value["name"] == "WriteFile"
                          and int(value["arguments"][2], 16) == 2048)
            assert detail["name"] == "WriteFile" and len(detail["arguments"]) == 5, detail
            assert "64 of 2048" in detail["text"] and detail["durationUs"] >= 0, detail
            # The inspector receives bounded typed payloads without adding buffers to the live page stream.
            assert detail["parameters"] and detail["caller"].startswith("0x"), detail
            buffer = next(value for value in detail["input"] if value["parameter"] == 1)
            assert buffer["kind"] == 0 and buffer["originalBytes"] == 2048 and buffer["flags"] & 1, buffer
            assert bytes.fromhex(buffer["bytes"]) == bytes(range(64)), buffer
            written = next(value for value in detail["output"] if value["parameter"] == 3)
            assert written["kind"] == 2 and int.from_bytes(bytes.fromhex(written["bytes"]), "little") == 2048
            assert all("input" not in item and "output" not in item for item in page["calls"])
            # Compact previews retain resource text and capture bounds without transferring complete payloads.
            preview = collector.call("page", database=database, api="WriteFile", limit=10, includeSummary=True)
            summary = next(item["summary"] for item in preview["calls"] if item["id"] == detail["id"]
                           and item["target"] == detail["target"])
            assert "64/2048 B" in summary, summary
            assert "lpNumberOfBytesWritten=" in summary and " → 0x800" in summary, summary
            assert all(len(item["summary"].encode("utf-8")) <= 768 and
                       "input" not in item and "output" not in item for item in preview["calls"])
            resource = collector.call("page", database=database, api="RegOpenKeyExW", limit=100, includeSummary=True)
            assert any('"Software"' in item["summary"] for item in resource["calls"]), resource
            assert all("summary" not in item for item in page["calls"])
            detail = next(value for value in details if value["name"] == "NtWriteFile"
                          and int(value["arguments"][6], 16) == 2048)
            assert len(detail["arguments"]) == 9 and "Information: 2048" in detail["text"], detail
            exports = collector.call("exports", path=str(collector_path.parent / "DetouristAgent.dll"))
            assert any(value["name"] == "DetouristStart" and value["executable"] for value in exports), exports

            # A parent exiting must not end capture while its followed child is still producing calls.
            database = str(root / "orphan.db")
            collector.call("launch", database=database, executable=str(target_path), arguments="--orphan 200")
            observed_orphan = False
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                status = collector.call("status")
                if status["processes"] == 2:
                    page = collector.call("page", database=database, limit=1)
                    parent, child = page["targets"]
                    coverage = child["nativeCoverage"]
                    assert coverage["installed"] > 0 and coverage["available"] <= coverage["catalog"], coverage
                    if parent["state"].startswith("Exited") and not child["state"].startswith("Exited"):
                        observed_orphan = True
                        assert not status["finished"], status
                if status["finished"]:
                    break
                time.sleep(0.02)
            assert observed_orphan and status["finished"], status
            page = collector.call("page", database=database, target=child["id"], api="NtWriteFile", limit=1000)
            assert sum(call["name"] == "NtWriteFile" and call["durationUs"] >= 0
                       for call in page["calls"]) >= 800, len(page["calls"])

            if cross_target := sibling_target(target_path):
                # Mixed-architecture child trees share the parent session; missing sibling agents report partial capture.
                database = str(root / "cross-child.db")
                status = collector.capture(database=database, executable=str(target_path),
                                           arguments=f'--child 10 "{cross_target}"', bufferLimit=64,
                                           apiMask=catalog["WriteFile"]["mask"], followChildren=True)
                assert status["processes"] == 2 and not status["partial"] and status["skippedChildren"] == 0, status
                with open_trace(database) as connection:
                    widths = {row[0] for row in connection.execute("SELECT pointer_size FROM targets")}
                    writes = dict(connection.execute("SELECT target,count(*) FROM calls WHERE api=? "
                        "AND substr(arguments,17,8)=? GROUP BY target",
                        (catalog["WriteFile"]["id"], struct.pack("<Q", 2048))))
                    assert widths == {4, 8} and writes == {1: 40, 2: 40}, (widths, writes)
                # Breakpoints carry the stopped process's width throughout a mixed-architecture capture.
                breakpoint_database = str(root / "cross-breakpoints.db")
                collector.call("launch", database=breakpoint_database, executable=str(target_path),
                    arguments=f'--child 1 "{cross_target}"', apiMask=catalog["WriteFile"]["mask"],
                    entryApi=catalog["WriteFile"]["id"], followChildren=True)
                previous = None
                stopped_widths = set()
                while True:
                    status = collector.wait(lambda value: value["finished"] or value["breakpoint"] and
                        (value["stoppedCall"]["pid"], value["stoppedCall"]["id"]) != previous)
                    if status["finished"]:
                        break
                    stopped = status["stoppedCall"]
                    targets = collector.call("page", database=breakpoint_database, limit=1)["targets"]
                    stopped_target = next(item for item in targets if item["id"] == stopped["target"])
                    assert stopped["pointerSize"] == stopped_target["pointerSize"], (stopped, stopped_target)
                    stopped_widths.add(stopped["pointerSize"])
                    previous = stopped["pid"], stopped["id"]
                    collector.call("continue", callId=stopped["id"], pid=stopped["pid"], tid=stopped["tid"])
                assert stopped_widths == {4, 8}, stopped_widths
                isolated = root / "isolated-collector"
                isolated.mkdir()
                for name in ("DetouristCollector.exe", "DetouristAgent.dll", "ApiCatalog.sqlite"):
                    shutil.copy2(collector_path.parent / name, isolated / name)
                with Collector(isolated / "DetouristCollector.exe") as partial_collector:
                    partial_database = str(root / "partial-child.db")
                    partial_collector.call("hello")
                    partial_status = partial_collector.capture(database=partial_database, executable=str(target_path),
                        arguments=f'--child 5 "{cross_target}"', bufferLimit=64,
                        apiMask=catalog["WriteFile"]["mask"], followChildren=True)
                    assert partial_status["processes"] == 1 and partial_status["partial"], partial_status
                    assert partial_status["skippedChildren"] == 1
                    assert "Partial capture finished" in partial_status["message"], partial_status

            # Views opened during capture pick up later calls, late arrivals and returns without indexing again.
            database = str(root / "followed.db")
            collector.call("launch", database=database, executable=str(target_path), arguments="--paced 300",
                           bufferLimit=64)
            status = collector.wait(lambda value: value["capturing"] and value["calls"] > 50 and os.path.exists(database))
            queries = {"all": {}, "failed": {"failuresOnly": True}, "slow": {"filter": "duration>20us"},
                       "writes": {"filter": "WriteFile -NtWriteFile"}}
            followed = {}
            for order in ("newest", "oldest"):
                for name, query in queries.items():
                    state = collector.call("view", database=database, order=order, includeMetadata=False, **query)
                    while not state["complete"]:
                        state.update(collector.call("view", view=state["view"], includeMetadata=False))
                    followed[order, name] = state
            extensions = 0
            while not status["finished"] or extensions == 0:
                status = collector.call("status")
                for state in followed.values():
                    update = collector.call("view", view=state["view"], includeMetadata=False)
                    assert update["complete"] and not update["stale"], update
                    extensions += update["changed"]
                    state.update(update)
                time.sleep(0.02)
            recorded = []
            query = {"database": database, "limit": 1000}
            while True:
                batch = collector.call("page", **query)["calls"]
                recorded.extend(batch)
                if len(batch) < query["limit"]:
                    break
                query.update(beforeTimestamp=batch[-1]["started"], beforeTarget=batch[-1]["target"],
                             beforeCallId=batch[-1]["id"], includeMetadata=False)
            keep = {"all": lambda call: True, "failed": lambda call: call["flags"] & 1,
                    "slow": lambda call: call["durationUs"] > 20,
                    "writes": lambda call: "writefile" in call["name"].lower()
                    and "ntwritefile" not in call["name"].lower()}
            assert len(recorded) == status["calls"] > 300 and extensions > 8, (len(recorded), status, extensions)
            for (order, name), state in followed.items():
                expected = [identity(call) for call in recorded if keep[name](call)]
                assert [identity(call) for call in collector.rows(state)] == (
                    expected if order == "newest" else expected[::-1]), (order, name, state["count"], len(expected))

            # Recorded images attribute callers; marks, seeking, totals and the timeline agree with the listed calls.
            state, rows = collector.view(database, "oldest")
            assert state["modules"] >= 3 and all("callerText" in row for row in rows[:50]), state["modules"]
            own = [identity(row) for row in rows
                   if row.get("callerText", "").lower().startswith("detouristtesttarget.exe+")]
            listed, calls = collector.view(database, "oldest", filter="from:app")
            assert own and [identity(row) for row in calls] == own, (len(own), listed["count"])
            collector.call("mark", view=state["view"], filters=["WriteFile", "", "duration>20us"])
            marked = collector.rows(state)
            assert [row["marks"] for row in marked] == [
                ("writefile" in row["name"].lower()) | (row["durationUs"] > 20) << 2 for row in marked]
            assert "Filter" in collector.call("mark", expected=False, view=state["view"], filters=["tid:x"])
            find, matches = collector.view(database, "oldest", filter="WriteFile -NtWriteFile")
            origin = rows[len(rows) // 2]
            later = [row for row in matches if (row["started"], row["target"], row["id"]) >
                     (origin["started"], origin["target"], origin["id"])]
            step = collector.call("seek", view=find["view"], target=origin["target"], callId=origin["id"], forward=True)
            assert (step["target"], step["callId"], step["count"]) == (
                later[0]["target"], later[0]["id"], len(matches)), step
            summary = collector.call("summary", view=state["view"], restart=True)
            while not summary["complete"]:
                summary = collector.call("summary", view=state["view"])
            assert {(item["module"], item["name"]): item["calls"] for item in summary["items"]} == collections.Counter(
                (row["module"], row["name"]) for row in rows)
            failed = sum(row["flags"] & 1 for row in rows)
            assert sum(item["failed"] for item in summary["items"]) == failed
            density = collector.call("timeline", view=state["view"], buckets=20)
            assert abs(sum(density["calls"]) - len(rows)) < 0.5 and sum(density["failures"]) == failed, density
            moment = rows[len(rows) // 3]["started"]
            assert collector.call("locate", view=state["view"], time=moment)["index"] == next(
                index for index, row in enumerate(rows) if row["started"] >= moment)
            parents = {(row["target"], row["parent"]) for row in rows if row["parent"]}
            parent = next(row for row in rows if (row["target"], row["id"]) in parents)
            _, children = collector.view(database, "oldest", filter=f"parent:{parent['target']}.{parent['id']}")
            assert [identity(row) for row in children] == [identity(row) for row in rows if row["parent"] ==
                                                           parent["id"] and row["target"] == parent["target"]]
            _, nested = collector.view(database, "oldest", filter=f"under:{parent['target']}.{parent['id']}")
            assert nested[0]["id"] == parent["id"] and {identity(row) for row in children} <= {
                identity(row) for row in nested}
            _, since = collector.view(
                database, "oldest", filter=f"after:{(moment - state['startClock']) / state['frequency']:.9f}")
            assert abs(len(since) - sum(row["started"] >= moment for row in rows)) <= 1, len(since)

            # Attach and stop preserve the independently launched process and its file workload.
            target = subprocess.Popen([str(target_path), "--paced", "700"],
                                      stdout=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            collector.call("attach", database=str(root / "attached.db"), pid=target.pid,
                           apiMask=catalog["WriteFile"]["mask"])
            collector.wait(lambda value: value["capturing"] and value["calls"] > 0)
            collector.call("pause", paused=True)
            collector.call("filters", apiMask=catalog["ReadFile"]["mask"])
            collector.call("pause", paused=False)
            collector.call("stop")
            status = collector.wait(lambda value: value["finished"])
            assert status["calls"] > 0, status
            assert target.wait(timeout=15) == 0
            target = None
            collector.close()

            # A disconnected interface releases an API breakpoint instead of stranding its target.
            collector = Collector(collector_path)
            target = subprocess.Popen([str(target_path), "--paced", "700"],
                                      stdout=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            collector.call("attach", database=str(root / "disconnected.db"), pid=target.pid,
                           entryMask=catalog["WriteFile"]["mask"], apiMask=catalog["WriteFile"]["mask"])
            status = collector.wait(lambda value: value["breakpoint"])
            stopped = status["stoppedCall"]
            assert stopped["name"] == "WriteFile" and stopped["pid"] == target.pid, status
            assert stopped["target"] > 0 and stopped["parameters"], stopped
            assert stopped["pointerSize"] == hello["pointerSize"], stopped
            assert collector.call("continue", expected=False, callId=stopped["id"] + 1)
            assert collector.call("writeMemory", expected=False, callId=stopped["id"] + 1,
                                  address=stopped["arguments"][1], bytes="00")
            collector.close()
            assert target.wait(timeout=15) == 0
            target = None
        finally:
            if target and target.poll() is None:
                target.kill()
                target.wait()
            if collector.process.poll() is None:
                collector.close()
    print("Collector IPC: launch, child capture, saved pages, indexed and followed views, callers, marks, "
          "seeking, totals, attach, controls, errors and disconnect passed.")


def records(database):
    with open_trace(database) as connection:
        return connection.execute(
            "SELECT c.target,c.id,COALESCE(d.name,a.name),COALESCE(d.category,a.category),c.ended "
            "FROM calls c LEFT JOIN apis a ON a.target=0 AND a.id=c.api "
            "LEFT JOIN apis d ON d.target=c.target AND d.id=c.api").fetchall()


def capture(collector, database, executable, categories, instructions=False, arguments="", **options):
    if executable.name.endswith("Tests.exe"):
        arguments = "--target " + arguments
    collector.capture(database=str(database), executable=str(executable), arguments=arguments,
        instructionEngine=instructions, bufferLimit=64, categoryMask=str(categories), timeout=100, **options)
    collector.require_exited(database)
    return records(database)


def reattach_policy(collector, arguments, root, catalog_path, first_category, second_category, mask):
    from TestSupport import wait_file

    result = root / "catalog-attach-result.txt"
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("COR_", "CORECLR_"))}
    target = subprocess.Popen([str(arguments.managed), str(result), "--attach"], env=environment,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    first_database = root / "catalog-attached.db"
    try:
        wait_file(result.with_suffix(".txt.ready"), target)
        for database, category, signal in ((first_database, first_category, ".txt.go"),
                (root / "catalog-reattached.db", second_category, ".txt.release")):
            if category == second_category:
                with closing(sqlite3.connect(catalog_path)) as connection:
                    connection.execute("UPDATE category_rules SET category_id=? WHERE position=6", (category,))
                    connection.commit()
            collector.call("attach", database=str(database), pid=target.pid, apiMask=mask,
                categoryMask=str(1 << category), instructionEngine=arguments.instructions, followChildren=False)
            status = collector.wait(lambda value: value["capturing"] or value["finished"])
            assert status["capturing"], status
            collector.wait(lambda value: collector.call("page", database=str(database), limit=1)
                ["targets"][0]["managedState"] == 1)
            result.with_suffix(signal).touch()
            if category == first_category:
                wait_file(result, target)
                assert result.read_text() == "managed-ok"
                collector.call("stop")
            else:
                assert target.wait(timeout=30) == 0, target.stderr.read().decode(errors="replace")
            collector.wait(lambda value: value["finished"])
            rows = records(database)
            assert rows and all(row[3] == category for row in rows), rows[:10]
            assert any("System.IO.BufferedStream.Read(" in row[2] for row in rows), rows[:10]
        assert all(row[3] == first_category for row in records(first_database))
    finally:
        collector.call("stop")
        collector.wait(lambda value: value["finished"])
        if target.poll() is None:
            target.kill()
            target.wait(timeout=10)
        target.stderr.close()


def catalog_policy(arguments, root):
    catalog_path = root / "ApiCatalog.sqlite"
    source_path = arguments.collector.parent / catalog_path.name
    with closing(sqlite3.connect(source_path)) as source, closing(sqlite3.connect(catalog_path)) as connection:
        source.backup(connection)
        categories = dict(connection.execute("SELECT name,id FROM categories"))
        registry, memory, data, files, devices = (categories[name] for name in
            ("Registry", "Memory", "Data and collections", "Files and storage", "Devices"))
        connection.execute("UPDATE categories SET name=?,description=? WHERE id=?",
            ("Catalog registry", "Catalog-defined description", registry))
        connection.execute("UPDATE category_rules SET position=position+10000")
        connection.executemany("INSERT INTO category_rules VALUES(?,?,?,?,?,?)", (
            (0, registry, "name", "exact", "writefile", None),
            (1, memory, "name", "prefix", "createfile", None),
            (2, data, "name", "exact", "createfilew", None),
            (3, None, "name", "prefix", "nt", "catalog_"),
            (4, files, "name", "contains", "catalog_writefile", None),
            (6, devices, "name", "contains", "system.io.", None),
            (7, data, "module", "contains", "msacm", None)))
        connection.commit()
    environment = {**os.environ, "DETOURIST_API_CATALOG": str(catalog_path)}
    with Collector(arguments.collector, env=environment) as collector:
        started = time.perf_counter()
        hello = collector.call("hello")
        print(f"Catalog policy and hello: {(time.perf_counter() - started) * 1000:.1f} ms", flush=True)
        labels = {item["id"]: item for item in hello["categories"]}
        assert labels[registry]["name"] == "Catalog registry"
        assert labels[registry]["description"] == "Catalog-defined description"
        known = {api["name"]: api for api in hello["catalog"]}
        assert known["WriteFile"]["category"] == registry
        assert known["CreateFileW"]["category"] == memory
        assert known["NtWriteFile"]["category"] == files
        assert known["acmStreamConvert"]["category"] == data

        # The same shared policy controls compiled hooks and dynamically discovered managed methods.
        target = arguments.child or arguments.win32 or arguments.managed
        if target:
            managed = target == arguments.managed
            category = devices if managed else registry
            options = {"apiMask": hello["managedMask"] if managed else known["WriteFile"]["mask"]}
            workload = f'"{root / "catalog-result.txt"}"' if managed else ""
            first_database = root / "catalog-before.db"
            rows = capture(collector, first_database, target, 1 << category, arguments.instructions,
                arguments=workload, **options)
            assert rows and all(row[3] == category for row in rows), rows[:10]
            if managed:
                assert sum("System.IO.BufferedStream.Read(" in row[2] for row in rows) == 36, rows[:10]
            else:
                assert all(row[2] == "WriteFile" for row in rows), rows[:10]
                call = collector.call("page", database=str(first_database), limit=1)["calls"][0]
                detail = collector.call("details", database=str(first_database),
                    target=call["target"], callId=call["id"])
                assert detail["categoryName"] == "Catalog registry", detail

            # Committed rule and label edits apply at the next capture boundary in the same controller.
            with closing(sqlite3.connect(catalog_path)) as connection:
                connection.execute("UPDATE category_rules SET category_id=? WHERE position=?",
                    (data, 6 if managed else 0))
                connection.execute("UPDATE categories SET name='Catalog data' WHERE id=?", (data,))
                connection.commit()
            if managed:
                workload = f'"{root / "catalog-updated-result.txt"}"'
            rows = capture(collector, root / "catalog-after.db", target, 1 << data, arguments.instructions,
                arguments=workload, **options)
            assert rows and all(row[3] == data for row in rows), rows[:10]
            assert all(row[3] == category for row in records(first_database))
            assert next(item for item in collector.call("hello")["categories"]
                if item["id"] == data)["name"] == "Catalog data"
            if managed:
                reattach_policy(collector, arguments, root, catalog_path, data, memory, hello["managedMask"])

            # An invalid replacement must fail before creating a capture and keep the last policy usable.
            valid_hello = collector.call("hello")
            for field, invalid in (("pattern", "x" * 384), ("target", "invalid"), ("category_id", 999)):
                with closing(sqlite3.connect(catalog_path)) as connection:
                    original = connection.execute(
                        "SELECT " + field + " FROM category_rules WHERE position=0").fetchone()[0]
                    connection.execute("PRAGMA ignore_check_constraints=ON")
                    connection.execute("UPDATE category_rules SET " + field + "=? WHERE position=0", (invalid,))
                    connection.commit()
                rejected_database = root / ("invalid-" + field + ".db")
                rejected = collector.call("launch", expected=False, database=str(rejected_database),
                    executable=str(target), arguments=workload, instructionEngine=arguments.instructions)
                assert "category" in rejected and not rejected_database.exists(), rejected
                assert collector.call("hello") == valid_hello
                with closing(sqlite3.connect(catalog_path)) as connection:
                    connection.execute("UPDATE category_rules SET " + field + "=? WHERE position=0", (original,))
                    connection.commit()
    print("Catalog category rules, labels, rewrites, reloads and validation passed.", flush=True)


def check_categories(arguments):
    with tempfile.TemporaryDirectory(prefix="Detourist-Categories-") as temporary:
        root = pathlib.Path(temporary)
        collector = Collector(arguments.collector)
        target = None
        try:
            hello = collector.call("hello")
            categories = {item["name"]: item for item in hello["categories"]}
            all_categories = int(hello["allCategories"])
            files = categories["Files and storage"]
            memory = categories["Memory"]
            registry = categories["Registry"]
            components = categories["COM and interoperability"]
            unknown = categories["Unclassified"]
            catalog = {(api["module"].lower(), api["name"]): api for api in hello["catalog"]}

            # The catalog should assign a useful purpose before users choose a category filter.
            expected_catalog_categories = {
                ("msi.dll", "MsiInstallProductW"): categories["System configuration"],
                ("pdh.dll", "PdhOpenQueryW"): categories["Diagnostics"],
                ("msacm32.dll", "acmStreamConvert"): categories["Media"],
                ("pathcch.dll", "PathCchCombine"): files,
                ("kernel32.dll", "CreateConsoleScreenBuffer"): categories["Windows and messages"],
                ("kernel32.dll", "CreateHardLinkW"): files,
                ("kernel32.dll", "GetDateFormatW"): categories["Text"],
                ("kernel32.dll", "CreateEnclave"): categories["Security"],
                ("ntdll.dll", "NtCreateTransaction"): categories["Data and collections"],
                ("ntdll.dll", "NtListenPort"): categories["Interprocess communication"],
                ("ntdll.dll", "NtTraceEvent"): categories["Diagnostics"],
                ("advapi32.dll", "AddAccessAllowedAce"): categories["Security"],
                ("advapi32.dll", "OpenEventLogW"): categories["Diagnostics"],
                ("advapi32.dll", "OpenSCManagerW"): categories["Services"]
            }
            for identity, category in expected_catalog_categories.items():
                assert catalog[identity]["category"] == category["id"], (identity, catalog[identity])
            assert not [api for api in hello["catalog"] if api["category"] == unknown["id"]]

            if arguments.win32:
                # Display categories span different API families without removing recorded calls.
                database = root / "all.db"
                rows = capture(collector, database, arguments.win32, all_categories, arguments.instructions)
                expected = {
                    "CreateFileA": files, "RegCreateKeyExA": registry, "CreateFileMappingW": memory,
                    "GetMessageW": categories["Windows and messages"], "socket": categories["Networking"],
                    "CreateCompatibleDC": categories["Graphics"], "BCryptGenRandom": categories["Security"],
                    "GetCurrentThreadId": categories["Processes and threads"],
                    "WaitForSingleObject": categories["Synchronization"],
                    "NtUserGetCursorPos": categories["Input"]
                }
                for name, category in expected.items():
                    matches = [row for row in rows if row[2] == name]
                    assert matches and all(row[3] == category["id"] for row in matches), (name, matches)
                for category in (files, memory, registry):
                    started = time.perf_counter()
                    page = collector.call("page", database=str(database), category=category["id"], limit=1000)
                    assert page["calls"] and all(call["category"] == category["id"] for call in page["calls"])
                    assert page["totalCalls"] == len(rows), page
                    print(f"{category['name']} display: {(time.perf_counter() - started) * 1000:.1f} ms")
                    call = page["calls"][0]
                    detail = collector.call("details", database=str(database), target=call["target"], callId=call["id"])
                    assert detail["categoryName"] == category["name"] and "Category:" in detail["text"]
                assert len(records(database)) == len(rows)
                assert collector.call("page", database=str(database), category=999, expected=False)

                # Capture filters suppress unrelated calls before their snapshots are copied.
                for category in (memory, registry):
                    rows = capture(collector, root / f"only-{category['id']}.db", arguments.win32,
                                   int(category["mask"]), arguments.instructions)
                    assert rows and all(row[3] == category["id"] for row in rows), rows[:10]

            if arguments.child:
                # Following children remains independent of filtering out process creation.
                database = root / "children.db"
                rows = capture(collector, database, arguments.child, int(files["mask"]),
                               arguments.instructions, arguments="--child 20", followChildren=True)
                assert len({row[0] for row in rows}) == 2 and all(row[3] == files["id"] for row in rows)
                excluded = capture(collector, root / "excluded-children.db", arguments.child, int(files["mask"]),
                                   arguments.instructions, arguments="--child 20", followChildren=True,
                                   excludedApis=["WriteFile", "GetFileAttributesW"])
                assert len({row[0] for row in excluded}) == 2
                assert all(row[2] not in ("WriteFile", "GetFileAttributesW") for row in excluded), excluded[:10]
                assert any(row[2] == "ReadFile" for row in excluded), excluded[:10]
                first = collector.call("page", database=str(database), category=files["id"], limit=10)
                call = first["calls"][0]
                filtered = collector.call("page", database=str(database), category=files["id"],
                                          target=call["target"], thread=call["tid"], limit=100)
                assert all(item["target"] == call["target"] and item["tid"] == call["tid"]
                           for item in filtered["calls"])
                second = collector.call("page", database=str(database), category=files["id"], offset=10, limit=10)
                assert not ({(item["target"], item["id"]) for item in first["calls"]} &
                            {(item["target"], item["id"]) for item in second["calls"]})

                # Breakpoints still fire with recording disabled; live category changes enable later calls.
                database = root / "live.db"
                write_api = next(api for api in hello["catalog"] if api["name"] == "WriteFile")
                target = subprocess.Popen([str(arguments.child), "--paced", "300"],
                                          stdout=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
                collector.call("attach", database=str(database), pid=target.pid, categoryMask="0",
                               instructionEngine=arguments.instructions, entryApi=write_api["id"])
                stopped = collector.wait(lambda value: value["breakpoint"])
                assert stopped["stoppedCall"]["name"] == "WriteFile", stopped
                collector.call("filters", categoryMask=files["mask"])
                collector.call("breakApi", entryApi=-1, exitApi=-1)
                collector.call("continue", callId=stopped["stoppedCall"]["id"])
                collector.wait(lambda value: value["finished"])
                exit_code = target.wait(timeout=15)
                assert exit_code == 0, f"Attached file fixture exited with 0x{exit_code & 0xFFFFFFFF:08X}"
                target = None
                rows = records(database)
                assert rows and all(row[3] == files["id"] for row in rows), rows[:10]

            if arguments.com:
                rows = capture(collector, root / "components.db", arguments.com, int(components["mask"]),
                               arguments.instructions)
                assert any(row[2] == "IDispatch::Invoke" for row in rows), rows[:10]
                assert all(row[3] == components["id"] for row in rows), rows[:10]
                excluded = capture(collector, root / "excluded-components.db", arguments.com,
                                   int(components["mask"]), arguments.instructions,
                                   excludedApis=["IDispatch::Invoke"])
                assert excluded and all(row[2] != "IDispatch::Invoke" for row in excluded), excluded[:10]
                assert any(row[2] == "IDispatch::GetTypeInfoCount" for row in excluded), excluded[:10]
                if arguments.instructions:
                    rows = capture(collector, root / "unknown-com.db", arguments.com, int(unknown["mask"]), True)
                    assert any("f2c7f242" in row[2].lower() and "slot 3" in row[2] for row in rows), rows[:10]
                    assert all(row[3] == unknown["id"] for row in rows), rows[:10]


            if arguments.syscalls:
                rows = capture(collector, root / "direct.db", arguments.syscalls, int(files["mask"]), True,
                               apiMask=hello["syscallMask"])
                assert len(rows) == 64 and all(row[2] == "NtWriteFile [syscall]" and row[4] is not None
                                             for row in rows), rows[:10]
                excluded = capture(collector, root / "excluded-direct.db", arguments.syscalls,
                                   int(files["mask"]), True, apiMask=hello["syscallMask"],
                                   excludedApis=["NtWriteFile"])
                assert not excluded, excluded[:10]

            if arguments.managed:
                result = root / "result.txt"
                rows = capture(collector, root / "managed.db", arguments.managed, int(files["mask"]),
                               arguments.instructions, arguments=f'"{result}"', apiMask=hello["managedMask"])
                assert result.read_text() == "managed-ok"
                assert sum("System.IO.BufferedStream.Read(uint8[], int32, int32)" in row[2]
                           and row[4] is not None for row in rows) == 36, rows[:10]
                assert all(row[3] == files["id"] for row in rows), rows[:10]
                name = next(row[2] for row in rows if "System.IO.BufferedStream.Read(" in row[2])
                result = root / "excluded-result.txt"
                excluded = capture(collector, root / "excluded-managed.db", arguments.managed,
                                   int(files["mask"]), arguments.instructions, arguments=f'"{result}"',
                                   apiMask=hello["managedMask"], excludedApis=[name])
                assert result.read_text() == "managed-ok"
                assert excluded and all(row[2] != name for row in excluded), excluded[:10]
            print("Functional capture and display filters passed.")
        finally:
            collector.call("stop")
            collector.wait(lambda value: value["finished"])
            if target and target.poll() is None:
                target.terminate()
                target.wait(timeout=15)
            collector.close()
        catalog_policy(arguments, root)


def inspect_console(pid):
    # Inspect the launched console without changing its input or interacting with unrelated terminals.
    handles = {index: kernel.GetStdHandle(index) for index in (-10, -11, -12)}
    kernel.FreeConsole()
    attached = kernel.AttachConsole(pid)
    try:
        assert attached, f"Cannot inspect cmd.exe console: {ctypes.get_last_error()}"
        members = (wintypes.DWORD * 32)()
        count = kernel.GetConsoleProcessList(members, len(members))
        assert 0 < count <= len(members) and pid in members[:count], "Console belongs to another process"
        window = kernel.GetConsoleWindow()
        bounds = wintypes.RECT()
        assert window and user.IsWindowVisible(window), "cmd.exe has no visible console window"
        assert user.IsIconic(window), "The non-interactive console check activated an ordinary window"
        assert user.GetForegroundWindow() != window, "The minimized console took the user's foreground focus"
        assert user.GetWindowRect(window, ctypes.byref(bounds)), "Cannot inspect console bounds"
        assert bounds.right > bounds.left and bounds.bottom > bounds.top, "Console window has no display area"
        return window
    finally:
        if attached:
            kernel.FreeConsole()
        for index, value in handles.items():
            kernel.SetStdHandle(index, value)


def check_console(collector_path, instructions):
    executable = str(pathlib.Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe")
    with tempfile.TemporaryDirectory(prefix="Detourist-Console-") as temporary:
        with Collector(collector_path) as collector:
            hello = collector.call("hello")
            for index in range(3):
                database = str(pathlib.Path(temporary) / f"console-{index}.db")
                process = None
                try:
                    # Exercise interactive console startup while the automated test stays minimized.
                    collector.call("launch", database=database, executable=executable, arguments="",
                                   bufferLimit=1024, apiMask=hello["allApis"], followChildren=True,
                                   instructionEngine=instructions)
                    status = collector.wait(lambda value: value["capturing"] or value["finished"])
                    assert status["capturing"], status
                    page = collector.call("page", database=database, limit=1)
                    assert len(page["targets"]) == 1, page
                    pid = page["targets"][0]["pid"]
                    process = kernel.OpenProcess(0x00101001, False, pid)
                    assert process, f"cmd.exe exited before inspection: {page}"
                    window = inspect_console(pid)
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        status = collector.call("status")
                        assert not status["finished"], f"Interactive cmd.exe exited during startup: {status}"
                        assert kernel.WaitForSingleObject(process, 0) == 258, "cmd.exe exited during capture"
                        page = collector.call("page", database=database, api="ReadConsole", limit=1)
                        if page["calls"]:
                            break
                        time.sleep(0.05)
                    assert page["calls"], "cmd.exe did not reach its interactive console read"
                    status = collector.wait(lambda value: value["calls"] > 0 or value["finished"])
                    assert not status["finished"], f"Interactive cmd.exe exited during startup: {status}"
                    assert status["calls"] > 0, "The visible command prompt was not traced"
                    time.sleep(0.5)
                    assert inspect_console(pid) == window, "cmd.exe lost its console during capture"
                    collector.call("stop")
                    collector.wait(lambda value: value["finished"])
                    assert kernel.WaitForSingleObject(process, 0) == 258, "Stopping capture terminated cmd.exe"
                    assert inspect_console(pid) == window, "Stopping capture hid the command prompt"
                    print(f"Visible cmd.exe launch {index + 1}/3 passed ({status['calls']} calls)", flush=True)
                finally:
                    if collector.process.poll() is None:
                        collector.call("stop")
                        collector.wait(lambda value: value["finished"])
                    if process:
                        kernel.TerminateProcess(process, 0)
                        kernel.WaitForSingleObject(process, 10000)
                        kernel.CloseHandle(process)


def check_instructions(collector_path, native_target, child_target):
    baseline = subprocess.run([str(native_target), "--runtime"], timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    assert baseline.returncode == 0, baseline
    with tempfile.TemporaryDirectory(prefix="Detourist-Instructions-") as temporary:
        root = pathlib.Path(temporary)
        collector = Collector(collector_path)
        try:
            hello = collector.call("hello")
            # The SDK contract survives a forwarded DLL export and bounds its newly allocated output.
            database = str(root / "allocated.db")
            collector.capture(database=database, executable=str(native_target), arguments="--allocated-buffers",
                              bufferLimit=64, apiMask=hello["allApis"], followChildren=False, instructionEngine=True)
            with open_trace(database) as connection:
                allocated = connection.execute("SELECT a.name,c.flags,c.result,c.arguments,c.output "
                    "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                    "WHERE a.name IN ('NetApiBufferAllocate','NetApiBufferReallocate','NetApiBufferFree',"
                    "'NetApiBufferSize') AND c.ended IS NOT NULL ORDER BY c.started").fetchall()
                assert len(allocated) == 5 and all(not row[1] & 256 for row in allocated), len(allocated)
                assert [row[0] for row in allocated] == ['NetApiBufferAllocate','NetApiBufferReallocate',
                    'NetApiBufferSize','NetApiBufferFree','NetApiBufferSize'], allocated[:1]
                for row, argument_count in zip(allocated, (2, 3, 2, 1, 2)):
                    assert len(row[3]) == argument_count * 8, row[:3]
                initial = values(allocated[0][4])
                assert any(value[0] == 1 and value[1] == 0 and value[2] & 1 and value[3] == 128 and
                           len(value[4]) == 64 for value in initial), initial
                resized = values(allocated[1][4])
                assert any(value[0] == 2 and value[1] == 0 and value[2] & 1 and value[3] == 384 and
                           value[4] == bytes(index ^ 0xA7 for index in range(64)) for value in resized), resized
                assert all(not row[1] & 1 and row[2] == 0 for row in allocated[:4]), [row[:3] for row in allocated]
                assert allocated[-1][1] & 1 and allocated[-1][2] == 87 and not allocated[-1][4], allocated[-1][:3]

            # Header metadata bounds real CRT buffers and counted strings without probing unused argument slots.
            database = str(root / "runtime.db")
            collector.call("launch", database=database, executable=str(native_target), arguments="--runtime",
                           bufferLimit=64, apiMask=hello["allApis"], followChildren=False, instructionEngine=True)
            collector.wait(lambda value: value["finished"], timeout=30)
            collector.require_exited(database)
            with open_trace(database) as connection:
                copies = connection.execute("SELECT c.arguments,c.flags,c.input,c.output,a.argument_count "
                    "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                    "WHERE a.name='memcpy' AND a.module='ucrtbase.dll' AND c.ended IS NOT NULL").fetchall()
                expected = bytes(index ^ 0xA5 for index in range(64))
                for length in (17, 4096):
                    matches = [row for row in copies if len(row[0]) == 24 and
                               struct.unpack_from("<Q", row[0], 16)[0] == length and
                               any(value[0] == 1 and value[4] == expected[:min(length, 64)]
                                   for value in values(row[2]))]
                    assert matches and all(row[4] == 3 and not row[1] & 256 for row in matches), (length, copies[:3])
                    for row in matches:
                        assert [(value[0], value[3], len(value[4])) for value in values(row[2])] == [
                            (1, length, min(length, 64))]
                        assert [(value[0], value[3], value[4]) for value in values(row[3])] == [
                            (0, length, expected[:min(length, 64)])]
                fills = connection.execute("SELECT c.arguments,c.input,c.output FROM calls c JOIN apis a "
                    "ON a.target=c.target AND a.id=c.api WHERE a.name IN ('memset','_o_memset') "
                    "AND c.ended IS NOT NULL").fetchall()
                assert any(struct.unpack_from("<QQ", row[0], 8) == (0x39, 23) and not values(row[1]) and
                           values(row[2]) == [(0, 0, 0, 23, bytes([0x39]) * 23)] for row in fills), fills[:2]
                comparisons = connection.execute("SELECT c.flags,c.input,c.output,a.argument_count "
                    "FROM calls c JOIN apis a ON a.target=c.target AND a.id=c.api "
                    "WHERE a.name='RtlCompareUnicodeString' AND c.ended IS NOT NULL").fetchall()
                left = "Runtime-export-first".encode("utf-16-le")
                right = "Runtime-export-second".encode("utf-16-le")
                assert any(row[3] == 3 and not row[0] & 256 and not values(row[2]) and
                           [(value[0], value[4]) for value in values(row[1]) if value[1] == 1] ==
                           [(0, left), (1, right)] and
                           [(value[0], len(value[4])) for value in values(row[1]) if value[1] == 0] ==
                           [(0, 16), (1, 16)]
                           for row in comparisons), comparisons[:2]
                zero = connection.execute("SELECT c.arguments,c.input,c.output,a.argument_count FROM calls c "
                    "JOIN apis a ON a.target=c.target AND a.id=c.api "
                    "WHERE a.name='RtlGetCurrentServiceSessionId' AND c.ended IS NOT NULL").fetchall()
                assert zero and all(not row[0] and not row[1] and not row[2] and row[3] == 0 for row in zero), zero
                assert not connection.execute("SELECT count(*) FROM diagnostics").fetchone()[0]
            # The remaining thread records calls after process teardown removes the observer workers.
            database = str(root / "teardown.db")
            attributes_mask = next(api["mask"] for api in hello["catalog"] if api["name"] == "GetFileAttributesW")
            collector.call("launch", database=database, executable=str(native_target), arguments="--teardown",
                           bufferLimit=64, apiMask=attributes_mask, followChildren=False, instructionEngine=True)
            collector.wait(lambda value: value["finished"], timeout=30)
            collector.require_exited(database)
            with open_trace(database) as connection:
                attributes = connection.execute("SELECT c.result,c.input FROM calls c JOIN apis a "
                    "ON a.id=c.api AND a.target=0 WHERE a.name='GetFileAttributesW' "
                    "AND c.ended IS NOT NULL").fetchall()
                expected = str(native_target).encode("utf-16-le")[:64]
                assert attributes and all(row[0] != 0xFFFFFFFF for row in attributes), attributes
                assert any(expected in row[1] for row in attributes), attributes
                assert not connection.execute("SELECT count(*) FROM diagnostics").fetchone()[0]
            # Creation can be filtered out while every child's initial workload is still captured.
            cases = [
                ("children", "--child 20", hello["allApis"], 80, 40, False),
                ("filtered", "--child 10", str(1 << 2), 40, 40, False),
                ("orphan", "--orphan 60", str(1 << 2), 0, 240, False),
            ]
            if cross_target := sibling_target(child_target):
                cases.append(("cross_children", f'--child 10 "{cross_target}"', str(1 << 2), 40, 40, True))
            for label, arguments, mask, parent_writes, child_writes, mixed in cases:
                database = str(root / f"{label}.db")
                status = collector.capture(database=database, executable=str(child_target), arguments=arguments,
                    bufferLimit=64, apiMask=mask, followChildren=True, instructionEngine=True, timeout=50)
                page = collector.call("page", database=database, limit=1)
                assert status["processes"] == 2 and not status["partial"] and status["skippedChildren"] == 0, status
                assert all(target["state"] == "Exited" for target in page["targets"]), page
                with open_trace(database) as connection:
                    if mixed:
                        assert {row[0] for row in connection.execute("SELECT pointer_size FROM targets")} == {4, 8}
                    writes = dict(connection.execute("SELECT target,count(*) FROM calls "
                        "WHERE api=2 AND substr(arguments,17,8)=? GROUP BY target", (struct.pack("<Q", 2048),)))
                    assert writes.get(2, 0) == child_writes, (label, writes)
                    assert writes.get(1, 0) == parent_writes, (label, writes)
                    assert not connection.execute("SELECT count(*) FROM diagnostics").fetchone()[0]
        except Exception:
            try:
                for target in collector.call("page", database=database, limit=1)["targets"]:
                    if target["state"] == "Capturing":
                        os.kill(target["pid"], signal.SIGTERM)
            except (OSError, RuntimeError):
                pass
            raise
        finally:
            collector.close()
    print("Instruction capture: SDK buffers, runtime contracts, teardown and child following passed.")


def runtime_module(api, handle):
    modules = (ctypes.c_void_p * 1024)()
    needed = ctypes.c_ulong()
    assert api.K32EnumProcessModulesEx(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3)
    assert needed.value <= ctypes.sizeof(modules)
    for module in modules[:needed.value // ctypes.sizeof(ctypes.c_void_p)]:
        text = ctypes.create_unicode_buffer(32768)
        if api.K32GetModuleFileNameExW(handle, module, text, len(text)) and \
                Path(text.value).name.casefold() == 'dynamorio.dll':
            return module


def check_detach(collector_path, target_path, artifact=None):
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    api.OpenProcess.restype = ctypes.c_void_p
    api.CloseHandle.argtypes = (ctypes.c_void_p,)
    api.K32EnumProcessModulesEx.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong)
    api.K32GetModuleFileNameExW.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong)

    context = nullcontext(str(artifact)) if artifact else tempfile.TemporaryDirectory(prefix='Detourist-Detach-')
    with context as directory:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        assert not list(root.glob('*.db')), 'Use a fresh capture directory.'
        checks = []
        with Collector(collector_path) as collector:
            hello = collector.call('hello')
            for mode in ('window', 'apc'):
                stem = root / mode
                target = subprocess.Popen([str(target_path), mode, str(stem)], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
                handle = api.OpenProcess(0x410, False, target.pid)
                assert handle
                try:
                    for phase in range(3):
                        prefix = Path(str(stem) + f'.{phase}')
                        wait_file(Path(str(prefix) + '.ready'), target, timeout=20)
                        collector.call('attach', pid=target.pid, database=str(root / f'{mode}-{phase}.db'),
                            instructionEngine=True, apiMask=hello['allApis'], bufferLimit=16, followChildren=False)
                        collector.wait(lambda state: state['capturing'])
                        address = runtime_module(api, handle)
                        assert address, 'The runtime was not visible during capture.'
                        Path(str(prefix) + '.go').touch()
                        callback = Path(str(prefix) + '.callback')
                        wait_file(callback, target, timeout=20)
                        deadline = time.monotonic() + 20
                        while callback.stat().st_size != 4:
                            assert target.poll() is None and time.monotonic() < deadline
                            time.sleep(0.02)
                        assert callback.read_bytes() == struct.pack('<I', 1), (mode, phase, callback.read_bytes())
                        collector.call('stop')
                        stopped = collector.wait(lambda state: state['finished'], timeout=20)
                        assert target.poll() is None, (mode, phase, target.poll())
                        assert runtime_module(api, handle) is None, 'The runtime remained mapped after detach.'
                        Path(str(prefix) + '.release').touch()
                        wait_file(Path(str(prefix) + '.done'), target, timeout=20)
                        checks.append(dict(mode=mode, session=phase, enteredCodeCache=True,
                            runtimeUnmapped=True, returnedAfterDetach=True, calls=stopped['calls']))
                        (root / 'audit.json').write_text(json.dumps(checks, indent=2), encoding='utf-8')
                        Path(str(prefix) + '.next').touch()
                    assert target.wait(timeout=15) == 0, (mode, target.returncode, target.stderr.read())
                finally:
                    if target.poll() is None:
                        target.kill()
                        target.wait()
                    api.CloseHandle(handle)
    print('Detach lifecycle: code-cache callbacks, runtime unmapping and native returns passed in six sessions.')


def check_breakpoint_recovery(collector_path, target_path):
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    with tempfile.TemporaryDirectory(prefix='Detourist-BreakpointRecovery-') as temporary:
        for phase in ('entryApi', 'exitApi'):
            for action in ('kill', 'continue', 'stop', 'disconnect'):
                collector = Collector(collector_path)
                process = None
                try:
                    api = next(item for item in collector.call('hello')['catalog'] if item['name'] == 'WriteFile')
                    collector.call('launch', database=str(Path(temporary) / f'{phase}-{action}.db'),
                        executable=str(target_path), arguments='--leaf 20', apiMask=api['mask'],
                        followChildren=False, **{phase: api['id']})
                    status = collector.wait(lambda value: value['breakpoint'] or value['finished'])
                    assert status['breakpoint'], status
                    process = kernel.OpenProcess(0x100001 | 0x1000, False, status['stoppedCall']['pid'])
                    assert process, ctypes.get_last_error()
                    assert kernel.WaitForSingleObject(process, 100) == 258, 'The breakpoint did not hold its target.'
                    if action == 'kill':
                        collector.process.kill()
                        collector.process.wait(timeout=5)
                    elif action == 'continue':
                        collector.call('breakApi', entryApi=-1, exitApi=-1)
                        collector.call('continue', callId=status['stoppedCall']['id'])
                    elif action == 'stop':
                        collector.call('stop')
                    else:
                        collector.close()
                    assert kernel.WaitForSingleObject(process, 10000) == 0, (phase, action, 'Target remained frozen')
                    code = wintypes.DWORD()
                    assert kernel.GetExitCodeProcess(process, ctypes.byref(code)) and code.value == 0, (
                        phase, action, code.value)
                    print(f'Breakpoint recovery: {phase}, {action} passed.', flush=True)
                finally:
                    if collector.process.poll() is None:
                        collector.close()
                    if process:
                        if kernel.WaitForSingleObject(process, 0) == 258:
                            kernel.TerminateProcess(process, 1)
                            kernel.WaitForSingleObject(process, 5000)
                        kernel.CloseHandle(process)


def check_nested_views(collector_path, target_path):
    with tempfile.TemporaryDirectory(prefix='Detourist-NestedViews-') as temporary:
        database = str(Path(temporary) / 'nested.db')
        with Collector(collector_path) as collector:
            api = next(item for item in collector.call('hello')['catalog'] if item['name'] == 'WriteFile')
            collector.capture(database=database, executable=str(target_path), arguments='--leaf 1',
                apiMask=api['mask'], followChildren=False)

        # Drive entry and return commits independently while keeping the production trace schema.
        with open_trace(database) as connection:
            connection.executescript('DELETE FROM calls; DELETE FROM targets; DELETE FROM threads;'
                "INSERT INTO targets VALUES(1,123,'probe.exe',0,0,'Capturing',8);"
                'INSERT INTO threads VALUES(1,1); UPDATE session SET total_calls=2;')
            insert = ('INSERT INTO calls(target,id,tid,api,started,ended,parent,depth,caller,result,error,'
                'flags,arguments) '
                f'VALUES(1,?,1,?,?,?,?,?,0,0,0,0,zeroblob({api["argumentCount"] * 8}))')
            connection.executemany(insert, [(1, api['id'], 100, None, 0, 0), (2, api['id'], 110, 120, 1, 1)])
            connection.commit()
            with Collector(collector_path) as collector:
                # A supplied schema cannot invoke callbacks that depend on private view state.
                for index, expression in enumerate(("api_match(999,1,1)", "has_text(x'41',x'',0)",
                        "has_argument(x'00',0)", "in_module(1,0,0,999)", "snapshot_match(1,1)",
                        "snapshot_ended(1,1)", "snapshot_flags(1,0)")):
                    crafted = Path(temporary) / f'schema-{index}.db'
                    with open_trace(crafted) as malicious:
                        connection.backup(malicious)
                        malicious.executescript('ALTER TABLE modules RENAME TO recorded_modules; '
                            f'CREATE VIEW modules AS SELECT * FROM recorded_modules WHERE {expression};')
                    error = collector.call('view', expected=False, database=str(crafted))
                    assert 'unsafe use of' in error, (expression, error)
                    assert collector.call('status')['finished']
                views = {}
                for order in ('oldest', 'newest'):
                    for text in ('under:1.1', '-under:1.1', 'parent:1.1'):
                        views[order, text] = collector.view(database, order, filter=text)[0]
                marked, _ = collector.view(database, 'oldest')
                collector.call('mark', view=marked['view'], filters=['under:1.1'])
                connection.execute('UPDATE calls SET ended=150 WHERE id=1')
                connection.executemany(insert, [(3, api['id'], 200, 250, 0, 0), (4, api['id'], 210, 220, 3, 1)])
                connection.execute('UPDATE session SET total_calls=4')
                connection.commit()
                for (order, text), state in views.items():
                    state.update(collector.call('view', view=state['view'], includeMetadata=False))
                    expected = {'under:1.1': [1, 2], '-under:1.1': [3, 4], 'parent:1.1': [2]}[text]
                    if order == 'newest':
                        expected = expected[::-1]
                    actual = [row['id'] for row in collector.rows(state)]
                    assert actual == expected, (order, text, actual, expected)
                    fresh, rows = collector.view(database, order, filter=text)
                    assert [row['id'] for row in rows] == expected
                    collector.call('release', view=fresh['view'])
                marked.update(collector.call('view', view=marked['view'], includeMetadata=False))
                assert [(row['id'], row['marks']) for row in collector.rows(marked)] == [
                    (1, 1), (2, 1), (3, 0), (4, 0)]
    print('Nested views: live and saved boundaries, both orders, exclusions, children and marks passed.')


def main_failures():
    parser = argparse.ArgumentParser()
    parser.add_argument('case', choices=('breakpoints', 'views'))
    parser.add_argument('collector', type=Path)
    parser.add_argument('target', type=Path)
    options = parser.parse_args()
    check = check_breakpoint_recovery if options.case == 'breakpoints' else check_nested_views
    check(options.collector.resolve(), options.target.resolve())


def main_collector():
    run_paths(check_collector, 'collector', 'target')


def main_categories():
    parser = path_parser('collector')
    for name in ("win32", "child", "com", "syscalls", "managed"):
        parser.add_argument("--" + name, type=pathlib.Path)
    parser.add_argument("--instructions", action="store_true")
    check_categories(parser.parse_args())


def main_console():
    parser = path_parser('collector')
    parser.add_argument("--instructions", action="store_true")
    arguments = parser.parse_args()
    check_console(arguments.collector.resolve(), arguments.instructions)


def main_instructions():
    run_paths(check_instructions, 'collector', 'native', 'children')


def main_detach():
    options = path_parser('collector', 'target', '--artifacts').parse_args()
    check_detach(options.collector.resolve(), options.target.resolve(),
        options.artifacts.resolve() if options.artifacts else None)


if __name__ == '__main__':
    run_scenarios({
        'failures': main_failures,
        'collector': main_collector,
        'categories': main_categories,
        'console': main_console,
        'instructions': main_instructions,
        'detach': main_detach,
    })
