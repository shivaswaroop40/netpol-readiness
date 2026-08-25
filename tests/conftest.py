import os

import pytest

from npready import Inventory

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def mini_inventory():
    return Inventory.from_manifests(os.path.join(FIXTURES, "mini_cluster.yaml"))
