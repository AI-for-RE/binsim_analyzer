import json
import os
import msgpack

from bindiff_types import Library, QualifiedName, ByteRange

from .tasks_common import Task

# Given a library that has been built+extracted (functions.json generated), build a map linking functions across all the provided library variants.
class MapTask(Task[tuple[Library, str]]):

    task_name = 'map'
    needs_temp = False
    needs_ghidra = False

    def do_task(self, task_args: tuple[Library, str]) -> None:

        library, extractions_dir  = task_args

        matching_extract_dirs = [dirname for dirname in os.listdir(extractions_dir) if library.name in dirname]
        self.write_log(f"Found {len(matching_extract_dirs)} library variants to analyze.")

        self.write_log("Building map of function variants...")
        functions_to_variants: dict[str, list[tuple[str, list[ByteRange]]]] = {} # Mapping of qualified name to all matching function entries across variants
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
                    for function in extracted_functions[archive_name][object_name]:

                        name = function['name']
                        byte_ranges = [ByteRange(r['begin_addr'], r['end_addr']) for r in function['byte_ranges']]
                        qualified_name = QualifiedName(archive_name, object_name, name)
                        function_variant = (extract_dirname, byte_ranges)

                        key = str(qualified_name)
                        if key in functions_to_variants:
                            functions_to_variants[key].append(function_variant)
                        else:
                            functions_to_variants[key] = [function_variant]
        
        # Check where each function appears -- it should appear at most once in each binary.
        self.write_log("Checking for any abnormal function entries...")
        for qualified_function_name in functions_to_variants:          
            function_variants = functions_to_variants[qualified_function_name]
            for variant_id in {v[0] for v in function_variants}:
                variant_appearances = [v[1] for v in function_variants if v[0] == variant_id]
                variant_count = len(variant_appearances)
                # If variant_count == 0, this likely indicates that the function was inlined.
                if variant_count > 1:
                    self.write_log(f"WARNING: Abnormality in {qualified_function_name} -- Variant {variant_id} contains function {qualified_function_name} {variant_count} times: \n\t{variant_appearances}.")

        # Serialize output
        self.write_log("Serializing function map...")
        serializable_map = {
            k: [(v[0], [(r.begin_addr, r.end_addr) for r in v[1]]) for v in variants]
            for k, variants in functions_to_variants.items()
        }
        output_path = os.path.join(self.output_dir, "function_map.msgpack")
        with open(output_path, 'wb') as f:
            f.write(msgpack.packb(serializable_map)) # type: ignore
        self.write_log(f"Function map written to {output_path}.")