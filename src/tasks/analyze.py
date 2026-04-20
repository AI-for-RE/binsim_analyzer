import json
import random
from statistics import mean
from typing import TYPE_CHECKING

from filelock import FileLock

from .tasks_common import Task
from bindiff_types import VariantPair, QualifiedName, ByteRange
import similarity as sim

import pyghidra

import os

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

# Qualified function name -> list of (compilation variant, ByteRange) pairs
FunctionMap = dict[str, list[tuple[str, list[ByteRange]]]]

# Analyze a batch of functions from a library's function map.
class AnalyzeTask(Task[tuple[str, FunctionMap]]):

    task_name = 'analyze'
    needs_temp = False
    needs_ghidra = True

    def do_task(self, task_args: tuple[str, FunctionMap]) -> None:


        import jpype
        JByteArray = jpype.JArray(jpype.JByte)

        (project_base_dir, functions_to_variants) = task_args

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
        #   variant_id -> object_path -> list of (function_key, byte_ranges)
        work: dict[str, dict[str, list[tuple[str, list[ByteRange]]]]] = {}
        for key, variants in functions_to_variants.items():
            qualified_function_name = QualifiedName.from_string(key)
            object_path = os.path.join(qualified_function_name.archive_name, qualified_function_name.object_name)
            for (variant_id, byte_ranges) in variants:
                work.setdefault(variant_id, {}).setdefault(object_path, []).append((key, byte_ranges))

        self.write_log(f"Extracting function bytes across {len(work)} variants...")

        # function_key -> variant_id -> bytes
        extracted_bytes: dict[str, dict[str, bytes]] = {}

        # Shuffle variants so concurrent AnalyzeTask workers are unlikely to contend on the same project.
        work_items = list(work.items())
        random.shuffle(work_items)

        for variant_id, objects in work_items:
            # Serialize access to each Ghidra project across workers. Ghidra's own lock raises instead of waiting,
            # so we wrap open_project in a FileLock and block until the project is free.
            lock_path = os.path.join(project_base_dir, f"{variant_id}.binsim.lock")
            self.write_log(f"Acquiring lock for project '{variant_id}'...")
            with FileLock(lock_path):
                self.write_log(f"Opening project '{variant_id}' in {project_base_dir}...")
                with pyghidra.open_project(project_base_dir, variant_id, create=False) as project:
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
                            for (function_key, byte_ranges) in functions:
                                function_bytes = bytes()
                                for byte_range in byte_ranges:
                                    start = byte_range.begin_addr
                                    length = byte_range.size()
                                    buf = JByteArray(length)
                                    n = file_bytes.getOriginalBytes(start, buf)
                                    function_bytes += bytes(buf[:n])
                                extracted_bytes.setdefault(function_key, {})[variant_id] = function_bytes

        self.write_log("Building function similarity matrices...")
        similarity_matrices: dict[str, list[VariantPair]] = {} # Dictionary mapping qualified function name to its similarity scores across all pairs of variants
        results: list[dict[str, object]] = []
        for key in functions_to_variants:

            self.write_log(f"Getting similarity for {key}...")

            variant_to_bytes = extracted_bytes.get(key, {})
            if not variant_to_bytes:
                self.write_log(f"WARNING: No byte data extracted for {key}, skipping similarity.")
                continue

            # Create similarity matrix across all variants
            variant_functions_list: list[tuple[str, bytes]] = sorted(variant_to_bytes.items(), key=(lambda v: v[0]))
            variant_pairs: list[VariantPair] = []
            n = len(variant_functions_list)
            # TODO: Once we have multiple ways of scoring similarity, abstract this into a function interface or something, iterate over all ways of producing a similarity matrix
            for i in range(n):
                v1 = variant_functions_list[i]
                for j in range(i, n):
                    v2 = variant_functions_list[j]
                    sim_score = sim.NCDSimilarity.compute_similarity(v1[1], v2[1])
                    variant_pairs.append(VariantPair(v1[0], v2[0], sim_score))

            similarity_matrices[key] = variant_pairs

        self.write_log("STABILITY SCORES:")
        for key in similarity_matrices:
            mean_similarity = float(mean([v.similiarity for v in similarity_matrices[key]]))
            results.append({
                'name': key,
                'stab_scores:': [
                    mean_similarity # TODO: Support multiple similarity scores
                ]
            })
            self.write_log(f"\t- {key} ({len(functions_to_variants[key])} variants): {mean_similarity}")

        # Serialize output
        out_file = os.path.join(self.output_dir, "analysis.json")
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2)

        self.write_log("Completed similarity analysis.")

        return