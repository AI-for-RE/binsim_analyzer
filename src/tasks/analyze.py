import json
import random
from statistics import mean
from typing import TYPE_CHECKING, Any

from filelock import FileLock

from tasks.map import FunctionMap

from tasks.tasks_common import Task
from bindiff_types import QualifiedName, ByteRange, SimilarityPair

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

        from generic.lsh.vector import WeightedLSHCosineVectorFactory, LSHVector
        from ghidra.features.bsim.query import GenSignatures
        from ghidra.xml import NonThreadedXmlPullParserImpl
        from ghidra.util.task import TaskMonitor
        from org.xml.sax.helpers import DefaultHandler
        from java.util import ArrayList

        import similarity as sim

        import jpype
        JByteArray = jpype.JArray(jpype.JByte)

        (extractions_base_dir, function_map) = task_args

        # Similarity analyzers to use in analysis
        similarity_analyzers: list[type[sim.SimilarityAnalyzer]] = [sim.NCDSimilarity, sim.BSimSimilarity]

        # Input data for the similarity analyzers (function_key -> variant_id -> analyzer name -> input value)
        analyzer_inputs: dict[QualifiedName, dict[str, dict[str, Any]]] = {}
        for key in function_map: analyzer_inputs[key] = {}

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
        # - [X] Ghidra BSim
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

                            self.write_log("Caching function bytes...")
                            entry_addrs = []
                            for function_key in functions:

                                analyzer_inputs[function_key].setdefault(variant_id, {})
                                
                                function = extracted_functions[function_key.archive_name][function_key.object_name][function_key.func_name]

                                # Extract entry point info for later BSim step
                                entry_point = function['entry_point']
                                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry_point)
                                entry_addrs.append(addr)

                                # Load function bytes
                                byte_ranges = [ByteRange(r['begin_addr'], r['end_addr']) for r in function['byte_ranges']]
                                function_bytes = bytes()
                                for byte_range in byte_ranges:
                                    start = byte_range.begin_addr
                                    length = byte_range.size()
                                    buf = JByteArray(length)
                                    n = file_bytes.getOriginalBytes(start, buf)
                                    function_bytes += bytes(buf[:n])
                                analyzer_inputs[function_key][variant_id]['ncd'] = function_bytes
                            
                            # Get the function signatures for the BSim analyzer
                            # TODO: Potentially do this in a separate bsim step if this bottlenecks the analysis time. Would allow for better use of parallelism
                            self.write_log("Caching function BSim signatures...")
                            ghidra_functions = [program.getFunctionManager().getFunctionAt(addr) for addr in entry_addrs]
                           
                            # Prepare for BSim signature generation
                            factory = WeightedLSHCosineVectorFactory()
                            weights_file = GenSignatures.getWeightsFile(program.getLanguageID(), program.getLanguageID())
                            with open(weights_file.getAbsolutePath()) as f:
                                parser = NonThreadedXmlPullParserImpl(f.read(), "weights", DefaultHandler(), False)
                                factory.readWeights(parser)
                            gensig = GenSignatures(False)
                            gensig.setVectorFactory(factory)
                            gensig.openProgram(program, None, None, None, None, None)

                            # Generate and cache signatures
                            gensig.scanFunctions(ArrayList(ghidra_functions).iterator(), len(ghidra_functions), TaskMonitor.DUMMY) # TODO: Use a proper task monitor?
                            mgr = gensig.getDescriptionManager() # pull the LSHVector for each scanned function via FunctionDescription → SignatureRecord → getLSHVector()
                            for exe_record in mgr.executableRecordSet:
                                for function_key in functions:
                                    function_desc = mgr.findFunctionByName(function_key.func_name, exe_record)
                                    # https://ghidra.re/ghidra_docs/api/ghidra/features/bsim/query/description/SignatureRecord.html
                                    signature = function_desc.getSignatureRecord()
                                    # TODO: If we wanted to save to a file, this is where we would call saveXml().
                                    vector = signature.getLSHVector()
                                    analyzer_inputs[function_key][variant_id]['bsim'] = vector

                            self.write_log("Cached all BSim signatures.")


        self.write_log("Building function similarity matrices...")
        similarity_matrices: dict[QualifiedName, list[SimilarityPair]] = {} # Dictionary mapping qualified function name to its similarity scores across all pairs of variants
        results: list[dict[str, object]] = []
        for key in function_map:

            variant_inputs = sorted(analyzer_inputs[key].items(), key=(lambda v: v[0]))
            n = len(variant_inputs)
            # if len(variant_inputs) == 0:
            #     self.write_log(f"WARNING: No data extracted for {key}, skipping similarity.")
            #     continue

            # Create similarity matrix across all variants
            similarity_matrices[key] = []
            for i in range(n):
                v1_name, v1_data = variant_inputs[i]
                for j in range(i, n):
                    v2_name, v2_data = variant_inputs[j]
                    sim_dict = {}
                    for analyzer_class in similarity_analyzers:
                        analyzer_name = analyzer_class.name()
                        if analyzer_name in v1_data and analyzer_name in v2_data:
                            sim_score = analyzer_class.compute_similarity(v1_data[analyzer_name], v2_data[analyzer_name])
                            sim_dict[analyzer_name] = sim_score
                        else:
                            if analyzer_name not in v1_data:
                                self.write_log(f"WARNING: Data for analyzer '{analyzer_name}' not found in function variant {key}:{v1_name}")
                            if analyzer_name not in v2_data:
                                self.write_log(f"WARNING: Data for analyzer '{analyzer_name}' not found in function variant {key}:{v2_name}")
                    similarity_matrices[key].append(SimilarityPair(v1_name, v2_name, sim_dict))

        self.write_log("STABILITY SCORES:")
        for key in similarity_matrices:
            stability_scores = [
                (analyzer_class.name(), float(mean([
                    sim_pair.sim_dict[analyzer_class.name()]
                    for sim_pair in similarity_matrices[key]
                    if analyzer_class.name() in sim_pair.sim_dict
                ])))
                for analyzer_class in similarity_analyzers
            ]
            results.append({
                'name': str(key),
                'stab_scores:': stability_scores
            })
            self.write_log(f"\t- {key} ({len(function_map[key].variants)} variants): {stability_scores}")

        # Serialize output
        out_file = os.path.join(self.output_dir, "analysis.json")
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2)

        self.write_log("Completed similarity analysis.")

        return