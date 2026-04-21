from dataclasses import dataclass
import json
import os
import pickle
from statistics import mean

from bindiff_types import FunctionEntry, Library, QualifiedName, ByteRange

from .tasks_common import Task

# (analysis priority, list of compilation variants)
# TODO: Use Variant class instead of str once that class is created
@dataclass
class FunctionMapEntry:
    weight: float
    variants: list[str]

FunctionMap = dict[QualifiedName, FunctionMapEntry]

# Get the analysis priority of a function via its list of variants
# Take into consideration its average size across binaries, and the amount of entries in the byte range list
def get_analysis_weight(variants: list[FunctionEntry]) -> float:
    # TODO: Factor in number of entries in byte range list?
    average_size = mean([sum([range.size() for range in v.byte_ranges]) for v in variants])
    return average_size

# Given a library that has been built+extracted (functions.json generated), build a map linking functions across all the provided library variants.
# This can be thought of as a pre-processing stage for the analysis stage.
# The task also produces some heuristics about whether a function is high-priority or not for the analysis stage.
class MapTask(Task[tuple[Library, str]]):

    task_name = 'map'
    needs_temp = False
    needs_ghidra = False

    def do_task(self, task_args: tuple[Library, str]) -> None:

        library, extractions_dir  = task_args

        matching_extract_dirs = [dirname for dirname in os.listdir(extractions_dir) if library.name in dirname]
        self.write_log(f"Found {len(matching_extract_dirs)} library variants to analyze.")

        self.write_log("Building map of function variants...")
        functions_to_entries: dict[QualifiedName, list[FunctionEntry]] = {}
        for extract_dirname in matching_extract_dirs:
            self.write_log(f"Processing functions in {extract_dirname}...")
            extracted_functions_file = os.path.join(extractions_dir, extract_dirname, "functions.json")
            try:
                with open(extracted_functions_file, 'r') as f:
                    extracted_functions = json.load(f)
            except FileNotFoundError:
                self.write_log(f"WARNING: functions.json file not found in {extract_dirname}, skipping this directory.")
                extracted_functions = []

            for archive_name in extracted_functions:
                for object_name in extracted_functions[archive_name]:
                    for (_, function) in extracted_functions[archive_name][object_name].items():

                        name = function['name']
                        qualified_name = QualifiedName(archive_name, object_name, name)
                        # Note this is a function entry but is "named" by the compilation variant rather than the actual function name
                        variant_entry = FunctionEntry(extract_dirname, [ByteRange(r['begin_addr'], r['end_addr']) for r in function['byte_ranges']])

                        if qualified_name in functions_to_entries:
                            functions_to_entries[qualified_name].append(variant_entry)
                        else:
                            functions_to_entries[qualified_name] = [variant_entry]
        
        # Check where each function appears -- it should appear at most once in each binary.
        self.write_log("Checking for any abnormal function entries...")
        for qualified_function_name in functions_to_entries:          
            function_variants = functions_to_entries[qualified_function_name]
            for variant in function_variants:
                variant_appearances = [v for v in function_variants if v.name == variant.name]
                variant_count = len(variant_appearances)
                # If variant_count == 0, this likely indicates that the function was inlined.
                if variant_count > 1:
                    self.write_log(f"WARNING: Abnormality in {qualified_function_name} -- Variant {variant.name} contains function {qualified_function_name} {variant_count} times: \n\t{variant_appearances}.")

        # Calculate analysis priorities and build final function map
        function_map: FunctionMap = {}
        self.write_log("Calculating analysis priorities...")
        for qualified_function_name in functions_to_entries:
            entries = functions_to_entries[qualified_function_name]
            weight = get_analysis_weight(entries)
            function_map[qualified_function_name] = FunctionMapEntry(weight, [e.name for e in entries])

        # Serialize output
        self.write_log("Serializing function map...")
        output_path = os.path.join(self.output_dir, "function_map.pkl")
        with open(output_path, 'wb') as f:
            pickle.dump(function_map, f)
        self.write_log(f"Function map written to {output_path}.")