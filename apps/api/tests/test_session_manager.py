from adbygod_api.core.session.manager import AUTH_LEVEL_RANK
from adbygod_api.models import AuthLevel

def test_auth_level_rank_order():
    assert AUTH_LEVEL_RANK[AuthLevel.ANON] < AUTH_LEVEL_RANK[AuthLevel.AUTHENTICATED]
    assert AUTH_LEVEL_RANK[AuthLevel.AUTHENTICATED] < AUTH_LEVEL_RANK[AuthLevel.LOCAL_ADMIN]
    assert AUTH_LEVEL_RANK[AuthLevel.LOCAL_ADMIN] < AUTH_LEVEL_RANK[AuthLevel.DOMAIN_ADMIN]
    assert AUTH_LEVEL_RANK[AuthLevel.DOMAIN_ADMIN] < AUTH_LEVEL_RANK[AuthLevel.DA_FOREST]
    assert AUTH_LEVEL_RANK[AuthLevel.DA_FOREST] < AUTH_LEVEL_RANK[AuthLevel.SYSTEM]
