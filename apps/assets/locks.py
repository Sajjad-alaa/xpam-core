from common.utils.lock import DistributedLock
from assets.models import Node


class NodeAddChildrenLock(DistributedLock):
    name_template = 'assets.node.add_children.<org_id:{org_id}>'

    def __init__(self, node: Node):
        name = self.name_template.format(org_id=node.org_id)
        super().__init__(name=name, release_on_transaction_commit=True)
