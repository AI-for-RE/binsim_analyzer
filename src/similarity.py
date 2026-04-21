from abc import ABC, abstractmethod
import lzma
from typing import Generic, TypeVar

from bindiff_types import SimilarityPair

T = TypeVar('T')

# Class defining a particular method of measuring function similarity
class SimilarityAnalyzer(ABC, Generic[T]):

    functions_list: list[T]

    @staticmethod
    @abstractmethod
    def name() -> str:
        """Name for the similarity metric."""
        ...

    @abstractmethod
    def compute_similarity(self, func_a: T, func_b: T) -> float:
        """ Computes similarity between 2 functions, returning a score between 0 (completely dissimilar) and 1 (identical)."""
        ...

    # Compute similarities across all pairs of functions in the provided dictionary
    def analyze_functions(self, functions: dict[str, T]) -> list[SimilarityPair]:
        n = len(functions)
        sorted_items = sorted(functions.items(), key=(lambda v: v[0]))
        output_pairs = []
        for i in range(n):
            v1 = sorted_items[i]
            for j in range(i, n):
                v2 = sorted_items[j]
                sim_score = self.compute_similarity(v1[1], v2[1])
                output_pairs.append(SimilarityPair(v1[0], v2[0], sim_score))
        return output_pairs

# Normalized Compression Distance (internally, uses the LZMA algorithm)
class NCDSimilarity(SimilarityAnalyzer[bytes]):

    @staticmethod
    def name() -> str:
        return 'ncd'
    
    def compute_similarity(self, func_a: bytes, func_b: bytes) -> float:

        # TODO: Look into filters, maybe we can improve the similarity using them

        filters = [
            #{"id": lzma.FILTER_X86, "start_offset": 0}, # TODO: Get start offsets from each binary file?
            {"id": lzma.FILTER_LZMA2}
        ]

        az = lzma.compress(func_a, format=lzma.FORMAT_RAW, filters=filters)
        bz = lzma.compress(func_b, format=lzma.FORMAT_RAW, filters=filters)
        abz= lzma.compress(func_a+func_b, format=lzma.FORMAT_RAW, filters=filters)
        az_len = len(az)
        bz_len = len(bz)
        abz_len = len(abz)

        ncd = (abz_len - min(az_len, bz_len))/max(az_len, bz_len)
        # Return the complement of NCD because similarity scores usually place 1 as most similar and 0 as least similar
        return 1 - ncd

# TODO: More similarity scores