from dataclasses import asdict

from .tasks_common import Task
from bindiff_types import FunctionEntry, Library, ByteRange

import os
import re
import json
from typing import TYPE_CHECKING, cast

import jpype
import pyghidra

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import Program
    from ghidra.program.model.address import AddressRange
    from ghidra.framework.model import DomainFile

# Gets the physical byte range for a virtual Ghidra address range
def file_range(program: Program, addr_range: AddressRange) -> ByteRange | None:
    memory = program.getMemory()
    start_info = memory.getAddressSourceInfo(addr_range.getMinAddress())
    if start_info is None:
        return None
    begin = start_info.getFileOffset()
    if begin < 0:
        return None  # uninitialized / synthetic / mapped — not backed by file bytes
    length = addr_range.getMaxAddress().getOffset() - addr_range.getMinAddress().getOffset() + 1
    return ByteRange(begin, begin + length)

class ExtractTask(Task[tuple[Library, str]]):

    task_name = 'extract'
    needs_temp = False
    needs_ghidra = True

    def do_task(self, task_args: tuple[Library, str]) -> None:

        from ghidra.formats.gfilesystem import GFileSystem, GFile

        library, build_dir = task_args

        archives_dict: dict[str, dict[str, list[FunctionEntry]]] = {} # Dictionary matching archives to its object files and functions

        # Walk through each archive file, load every binary, and save it to the project if it doesn't exist yet
        with pyghidra.open_project(self.output_dir, self.task_id, create=True) as project:
            for archive_path in library.archives:
                self.write_log(f"=== BEGIN EXTRACTION FOR {archive_path} ===")
                archive_id = archive_path.replace("/", "_")
                archives_dict[archive_id] = {}
                archive_import_dir = f"/{archive_id}"
                full_archive_path = os.path.join(os.path.abspath(build_dir), archive_path) # archive_path is a relative directory

                with pyghidra.open_filesystem(full_archive_path) as fs:
                    fs = cast(GFileSystem, fs) # Makes my life easier for writing and understanding the code
                    loader = pyghidra.program_loader().project(project)

                    for f in fs.files():
                        f = cast(GFile, f)
                        if re.fullmatch(r".*\.o", f.getName()):
                            self.write_log(f"Importing file {f.getPath()}...")
                            loader = loader.source(f.getFSRL()).projectFolderPath(archive_import_dir + str(f.parentFile.name))
                            with loader.load() as load_results:
                                load_results.save(pyghidra.task_monitor())

                self.write_log("All imports completed.")

                # Get function byte ranges, build function map
                # # Features to enable:
                # - DWARF: Processes the DWARF information
                # - Disassemble Entry Points: Disassembles functions from Ghidra function entry points (which were created by the DWARF analyzer)

                self.write_log("Extracting functions from object files in archive...")
                options_to_set = ["DWARF", "Disassemble Entry Points"] # Enable Decompiler Parameter ID? This would be very time-consuming though
                options_to_disable = []

                # Necessary to get around weird timing error, potentially caused by WSL2 timing synchronisation glitches. Might not be necessary outside of WSL
                def _safe_analyze(program: Program) -> None:
                    import jpype
                    from ghidra.app.script import GhidraScriptUtil
                    from ghidra.program.util import GhidraProgramUtilities
                    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

                    monitor = pyghidra.task_monitor()
                    with pyghidra.transaction(program, "Analyze"):
                        GhidraScriptUtil.acquireBundleHostReference()
                        try:
                            mgr = AutoAnalysisManager.getAnalysisManager(program)
                            mgr.initializeOptions()
                            mgr.reAnalyzeAll(None)
                            try:
                                mgr.startAnalysis(monitor, True)
                            except jpype.JException as e:
                                trace = e.stacktrace()
                                if "getTaskTimesString" in trace or "printTimedTasks" in trace:
                                    pass
                                else:
                                    raise
                            if not monitor.isCancelled():
                                monitor.cancel()
                            GhidraProgramUtilities.markProgramAnalyzed(program)
                        finally:
                            GhidraScriptUtil.releaseBundleHostReference()

                def _extract_function_entries(_: DomainFile, program: Program) -> None:
                    obj_name = program.getName()
                    self.write_log(f"Analyzing program {obj_name}...")
                    analysis_props = pyghidra.analysis_properties(program)
                    with pyghidra.transaction(program):
                        for option_name in options_to_set:
                            analysis_props.setBoolean(option_name, True)
                        for option_name in options_to_disable:
                            analysis_props.setBoolean(option_name, False)
                    # Do the analysis.
                    try:
                        # analysis_log = pyghidra.analyze(program, pyghidra.task_monitor())
                        _safe_analyze(program)
                    except jpype.JException as e:
                        self.write_log(f"ERROR: Java exception in analyze for {obj_name}:\n{e.stacktrace()}")
                        raise
                    program.save("Analyzed", pyghidra.task_monitor())

                    # Extract functions and add to the dictionary
                    self.write_log("Analysis completed, now extracting functions...")
                    functions: list[FunctionEntry] = []
                    function_manager = program.getFunctionManager()
                    for function in function_manager.getFunctions(True):
                        # getBody() returns an AddressSetView; getAddressRanges() yields
                        # the maximal contiguous ranges, which naturally covers hot/cold
                        # splits. Ghidra's max address is inclusive, so +1 for an
                        # exclusive end to match the DWARF-extracted ByteRange semantics.
                        byte_ranges = [ r for r in (
                                file_range(program, addr_range)
                                for addr_range in function.getBody().getAddressRanges()
                            )
                            if r is not None
                        ]
                        if byte_ranges:
                            functions.append(FunctionEntry(function.getName(), function.getEntryPoint().getOffset(), byte_ranges))
                        else:
                            self.write_log(f"DEBUG: Skipping function {function.getName()} (no file-backed body).")

                    if len(functions) > 0:
                        self.write_log(f"Function extraction successful -- extracted {len(functions)} functions from object file.")
                    else:
                        self.write_log("WARNING: Function extraction yielded zero functions; make sure DWARF information is present.")
                    archives_dict[archive_id][obj_name] = functions
    
                pyghidra.walk_programs(project, _extract_function_entries, start=archive_import_dir)

        self.write_log("Serializing output...")

        # Serialize results
        serialized_archives = {
            archive: {
                obj: {
                    f.name: asdict(f)
                    for f in functions
                }
                for obj, functions in obj_files.items()
            }
            for archive, obj_files in archives_dict.items()
        }
        functions_path = os.path.join(self.output_dir, "functions.json")
        with open(functions_path, "w") as f:
            json.dump(serialized_archives, f, indent=2)

        self.write_log("Output successfully saved.")

        return