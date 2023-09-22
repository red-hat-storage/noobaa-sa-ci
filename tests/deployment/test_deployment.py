import logging
from deployment.deployment import Deployment

log = logging.getLogger(__name__)


def test_deployment():
    dep = Deployment()
    dep.install_noobaa_sa()
