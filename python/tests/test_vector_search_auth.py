import os
import tempfile

import numpy as np

from qihse.core import DistanceMetric, VectorDB


def test_vector_search_supplies_authenticated_user():
    with tempfile.TemporaryDirectory() as temp_dir:
        path = os.path.join(temp_dir, "auth-search.qdb")
        vectors = np.eye(4, dtype=np.float32)

        with VectorDB.create(path, dims=4) as database:
            database.add_vectors(vectors, ids=[10, 11, 12, 13])
            database.build_graph()
            results = database.search(
                vectors[2],
                k=2,
                metric=DistanceMetric.COSINE,
            )

        assert results
        assert results[0].id == 12
