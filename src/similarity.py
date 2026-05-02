from abc import ABC, abstractmethod
import lzma
from typing import Generic, TypeVar, TYPE_CHECKING

from bindiff_types import SimilarityPair

from generic.lsh.vector import LSHVector, VectorCompare


T = TypeVar('T')

# Class defining a particular method of measuring function similarity
class SimilarityAnalyzer(ABC, Generic[T]):

    functions_list: list[T]

    @staticmethod
    @abstractmethod
    def name() -> str:
        """Name for the similarity metric."""
        ...

    @staticmethod
    @abstractmethod
    def compute_similarity(func_a: T, func_b: T) -> float:
        """ Computes similarity between 2 functions, returning a score between 0 (completely dissimilar) and 1 (identical)."""
        ...        

# Normalized Compression Distance (internally, uses the LZMA algorithm)
class NCDSimilarity(SimilarityAnalyzer[bytes]):

    @staticmethod
    def name() -> str:
        return 'ncd'
    
    @staticmethod
    def compute_similarity(func_a: bytes, func_b: bytes) -> float:

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

# BSim
class BSimSimilarity(SimilarityAnalyzer[LSHVector]):

    @staticmethod
    def name() -> str:
        return 'bsim'

    @staticmethod
    def compute_similarity(func_a: LSHVector, func_b: LSHVector) -> float:
        
        cmp = VectorCompare()
        similarity  = func_a.compare(func_b, cmp)           # 0..1
        #significance = factory.calculateSignificance(cmp)  # TODO: Significance?
        return similarity
    