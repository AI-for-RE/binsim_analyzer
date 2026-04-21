import json
import random
from statistics import mean
from typing import TYPE_CHECKING

from filelock import FileLock

from tasks.map import FunctionMap

from tasks.tasks_common import Task
from bindiff_types import QualifiedName, ByteRange, SimilarityPair
import similarity as sim

import pyghidra

import os

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

# Analyze a batch of functions from a library's function map.
class AnalyzeTask(Task[tuple[str, FunctionMap]]):

    task_name = 'analyze'
    needs_temp = False
    needs_ghidra = True

    def do_task(self, task_args: tuple[str, FunctionMap]) -> None:

        import jpype
        JByteArray = jpype.JArray(jpype.JByte)

        (extractions_base_dir, function_map) = task_args

        # TODO:
        # - Based on a choice of similarity metric, determine stability score of each function:
        #     - [X] Calculate similarity score of function to all of its variants
        #     - [ ] Write scores to a file in a useful format (so that the data is persistent)
        #     - [ ] Gather statistics from this list of similarity scores to generate stability estimate
        #         - Maybe only consider a subset of variants in this analysis? or not?
        # - [ ] Organize/rank functions by their stability score

        # Determine similarity scores
        # TODO: Different similarity scores:
        # - [X] Basic information-theoretic similarity (NCD with LZMA)
        # - [ ] Ghidra BSim
        # - [ ] Other methods (e.g. BCSD models?)

        # Group the work so each Ghidra project, and each program within the project, is opened exactly once.
        #   variant_id -> object_path -> function key
        work: dict[str, dict[str, list[QualifiedName]]] = {}
        for qualified_function_name, entry in function_map.items():
            variants = entry.variants
            object_path = os.path.join(qualified_function_name.archive_name, qualified_function_name.object_name)
            for variant_id in variants:
                work.setdefault(variant_id, {}).setdefault(object_path, []).append(qualified_function_name)

        self.write_log(f"Extracting function bytes across {len(work)} variants...")

        # function key -> variant_id -> bytes
        extracted_bytes: dict[QualifiedName, dict[str, bytes]] = {}

        # Shuffle variants so concurrent AnalyzeTask workers are unlikely to contend on the same project.
        work_items = list(work.items())
        random.shuffle(work_items)

        for variant_id, objects in work_items:
            # Serialize access to each Ghidra project across workers. Ghidra's own lock raises instead of waiting,
            # so we wrap open_project in a FileLock and block until the project is free.
            extract_dir = os.path.abspath(os.path.join(extractions_base_dir, variant_id))
            lock_path = os.path.join(extract_dir, f"{variant_id}.binsim.lock")
            self.write_log(f"Acquiring lock for project '{variant_id}'...")
            with FileLock(lock_path):
                # Open functions JSON
                # Note that function JSON files (like the Ghidra projects) are indexed by variant ID so the earlier lock is enough for to avoid concurrency issues
                json_path = os.path.join(extract_dir, "functions.json")
                self.write_log(f"Loading function metadata file {json_path}...")
                with open(json_path) as f:
                    extracted_functions = json.load(f)
                self.write_log(f"Opening project '{variant_id}' in {extract_dir}...")
                with pyghidra.open_project(extract_dir, variant_id, create=False) as project:
                    for object_path, functions in objects.items():
                        project_object_path = "/" + object_path
                        try:
                            program_ctx = pyghidra.program_context(project, project_object_path)
                        except FileNotFoundError:
                            self.write_log(f"WARNING: {project_object_path} not found in project {variant_id}, skipping {len(functions)} function(s).")
                            continue
                        with program_ctx as program:
                            (file_bytes,) = program.getMemory().getAllFileBytes()
                            expected_name = os.path.basename(object_path)
                            actual_name = str(file_bytes.getFilename())
                            if actual_name != expected_name:
                                self.write_log(f"WARNING: file_bytes name '{actual_name}' does not match object name '{expected_name}' for {project_object_path}.")

                            for function_key in functions:
                                
                                function = extracted_functions[function_key.archive_name][function_key.object_name][function_key.func_name]

                                # Load function bytes
                                byte_ranges = [ByteRange(r['begin_addr'], r['end_addr']) for r in function['byte_ranges']]
                                function_bytes = bytes()
                                for byte_range in byte_ranges:
                                    start = byte_range.begin_addr
                                    length = byte_range.size()
                                    buf = JByteArray(length)
                                    n = file_bytes.getOriginalBytes(start, buf)
                                    function_bytes += bytes(buf[:n])
                                extracted_bytes.setdefault(function_key, {})[variant_id] = function_bytes
                                
                                # TODO: Get the function signatures for the BSim analyzer
                                entry_point = function['entry_point']
                                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry_point)


        self.write_log("Building function similarity matrices...")
        similarity_matrices: dict[QualifiedName, list[SimilarityPair]] = {} # Dictionary mapping qualified function name to its similarity scores across all pairs of variants
        results: list[dict[str, object]] = []
        for key in function_map:

            self.write_log(f"Getting similarity for {key}...")

            variant_to_bytes = extracted_bytes.get(key, {})
            if not variant_to_bytes:
                self.write_log(f"WARNING: No byte data extracted for {key}, skipping similarity.")
                continue

            # Create similarity matrix across all variants
            similarity_analyzer = sim.NCDSimilarity()
            variant_pairs = similarity_analyzer.analyze_functions(variant_to_bytes)
            similarity_matrices[key] = variant_pairs

        self.write_log("STABILITY SCORES:")
        for key in similarity_matrices:
            mean_similarity = float(mean([v.similiarity for v in similarity_matrices[key]]))
            results.append({
                'name': str(key),
                'stab_scores:': [
                    mean_similarity # TODO: Support multiple similarity scores
                ]
            })
            self.write_log(f"\t- {key} ({len(function_map[key].variants)} variants): {mean_similarity}")

        # Serialize output
        out_file = os.path.join(self.output_dir, "analysis.json")
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2)

        self.write_log("Completed similarity analysis.")

        return